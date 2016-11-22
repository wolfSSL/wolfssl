# -*- coding: utf-8 -*-
#
# __init__.py
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

from wolfssl._methods import (
    PROTOCOL_SSLv23, PROTOCOL_SSLv3, PROTOCOL_TLSv1,
    PROTOCOL_TLSv1_1, PROTOCOL_TLSv1_2, PROTOCOL_TLS
)

from wolfssl._context import (
    SSLContext, CERT_NONE, CERT_OPTIONAL, CERT_REQUIRED
)

from wolfssl._socket import SSLSocket

from wolfssl._exceptions import (
    CertificateError, SSLError, SSLEOFError, SSLSyscallError,
    SSLWantReadError, SSLWantWriteError, SSLZeroReturnError
)

from wolfssl.__about__ import (
    __all__, METADATA
)

globals().update(METADATA)

def wrap_socket(sock, keyfile=None, certfile=None, server_side=False,
                cert_reqs=CERT_NONE, ssl_version=PROTOCOL_TLS, ca_certs=None,
                do_handshake_on_connect=True, suppress_ragged_eofs=True,
                ciphers=None):
    """
    Takes an instance sock of socket.socket, and returns an instance of
    wolfssl.SSLSocket, a subtype of socket.socket, which wraps the underlying
    socket in an SSL context. sock must be a SOCK_STREAM socket; other socket
    types are unsupported.

    For client-side sockets, the context construction is lazy; if the underlying
    socket isn’t connected yet, the context construction will be performed after
    connect() is called on the socket. For server-side sockets, if the socket
    has no remote peer, it is assumed to be a listening socket, and the
    server-side SSL wrapping is automatically performed on client connections
    accepted via the accept() method. wrap_socket() may raise SSLError.

    The keyfile and certfile parameters specify optional files which contain a
    certificate to be used to identify the local side of the connection.

    The parameter server_side is a boolean which identifies whether server-side
    or client-side behavior is desired from this socket.

    The parameter cert_reqs specifies whether a certificate is required from the
    other side of the connection, and whether it will be validated if provided.
    It must be one of the three values:
        CERT_NONE (certificates ignored)
        CERT_OPTIONAL (not required, but validated if provided)
        CERT_REQUIRED (required and validated)

    If the value of this parameter is not CERT_NONE, then the ca_certs parameter
    must point to a file of CA certificates.

    The ca_certs file contains a set of concatenated “certification authority”
    certificates, which are used to validate certificates passed from the other
    end of the connection.

    The parameter ssl_version specifies which version of the SSL protocol to
    use. Typically, the server chooses a particular protocol version, and the
    client must adapt to the server’s choice. Most of the versions are not
    interoperable with the other versions. If not specified, the default is
    PROTOCOL_TLS; it provides the most compatibility with other versions.

    Here’s a table showing which versions in a client (down the side) can
    connect to which versions in a server (along the top):

    | client \\ server | SSLv3 | TLS | TLSv1 | TLSv1.1 | TLSv1.2 |
    | SSLv3            | yes   | yes | no    | no      | no      |
    | TLS (SSLv23)     | yes   | yes | yes   | yes     | yes     |
    | TLSv1            | no    | yes | yes   | no      | no      |
    | TLSv1.1          | no    | yes | no    | yes     | no      |
    | TLSv1.2          | no    | yes | no    | no      | yes     |

    Note:
        Which connections succeed will vary depending on the versions of the ssl
        providers on both sides of the communication.

    The ciphers parameter sets the available ciphers for this SSL object. It
    should be a string in the wolfSSL cipher list format.

    The parameter do_handshake_on_connect specifies whether to do the SSL
    handshake automatically after doing a socket.connect(), or whether the
    application program will call it explicitly, by invoking the
    SSLSocket.do_handshake() method. Calling SSLSocket.do_handshake() explicitly
    gives the program control over the blocking behavior of the socket I/O
    involved in the handshake.

    The parameter suppress_ragged_eofs specifies how the SSLSocket.recv() method
    should signal unexpected EOF from the other end of the connection. If
    specified as True (the default), it returns a normal EOF (an empty bytes
    object) in response to unexpected EOF errors raised from the underlying
    socket; if False, it will raise the exceptions back to the caller.
    """
    return SSLSocket(sock=sock, keyfile=keyfile, certfile=certfile,
                     server_side=server_side, cert_reqs=cert_reqs,
                     ssl_version=ssl_version, ca_certs=ca_certs,
                     do_handshake_on_connect=do_handshake_on_connect,
                     suppress_ragged_eofs=suppress_ragged_eofs,
                     ciphers=ciphers)
