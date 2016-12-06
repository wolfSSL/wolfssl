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
import errno
from socket import socket, AF_INET, SOCK_STREAM, SOL_SOCKET, SO_TYPE

try:
    from wolfssl._ffi import ffi as _ffi
    from wolfssl._ffi import lib as _lib
except ImportError:
    pass

from wolfssl.utils import t2b

from wolfssl._exceptions import (
    CertificateError, SSLError, SSLEOFError, SSLSyscallError,
    SSLWantReadError, SSLWantWriteError, SSLZeroReturnError
)

from wolfssl._methods import (
    PROTOCOL_SSLv23, PROTOCOL_SSLv3, PROTOCOL_TLSv1,
    PROTOCOL_TLSv1_1, PROTOCOL_TLSv1_2, PROTOCOL_TLS,
    WolfSSLMethod as _WolfSSLMethod
)

from wolfssl.__about__ import (
    __all__, METADATA
)

globals().update(METADATA)

CERT_NONE = 0
CERT_OPTIONAL = 1
CERT_REQUIRED = 2

_VERIFY_MODE_LIST = [CERT_NONE, CERT_OPTIONAL, CERT_REQUIRED]

_SSL_SUCCESS = 1
_SSL_FILETYPE_PEM = 1

class SSLContext(object):
    """
    An SSLContext holds various SSL-related configuration options and
    data, such as certificates and possibly a private key.
    """

    def __init__(self, protocol, server_side=False):
        method = _WolfSSLMethod(protocol, server_side)

        self.protocol = protocol
        self._side = server_side
        self._verify_mode = None
        self.native_object = _lib.wolfSSL_CTX_new(method.native_object)

        # wolfSSL_CTX_new() takes ownership of the method.
        # the method is freed later inside wolfSSL_CTX_free()
        # or if wolfSSL_CTX_new() failed to allocate the context object.
        method.native_object = None

        if self.native_object == _ffi.NULL:
            raise MemoryError("Unnable to allocate context object")

        # verify_mode initialization needs a valid native_object.
        self.verify_mode = CERT_NONE


    def __del__(self):
        if self.native_object is not None:
            _lib.wolfSSL_CTX_free(self.native_object)


    @property
    def verify_mode(self):
        """
        Whether to try to verify other peers’ certificates and how to behave
        if verification fails. This attribute must be one of CERT_NONE,
        CERT_OPTIONAL or CERT_REQUIRED.
        """
        return self._verify_mode


    @verify_mode.setter
    def verify_mode(self, value):
        if value not in _VERIFY_MODE_LIST:
            raise ValueError("verify_mode must be one of CERT_NONE, "
                             "CERT_OPTIONAL or CERT_REQUIRED")

        if value != self._verify_mode:
            self._verify_mode = value
            _lib.wolfSSL_CTX_set_verify(self.native_object,
                                        self._verify_mode,
                                        _ffi.NULL)


    def wrap_socket(self, sock, server_side=False,
                    do_handshake_on_connect=True,
                    suppress_ragged_eofs=True,
                    server_hostname=None):
        """
        Wrap an existing Python socket sock and return an SSLSocket object.
        sock must be a SOCK_STREAM socket; other socket types are unsupported.

        The returned SSL socket is tied to the context, its settings and
        certificates. The parameters server_side, do_handshake_on_connect and
        suppress_ragged_eofs have the same meaning as in the top-level
        wrap_socket() function.
        """
        return SSLSocket(sock=sock, server_side=server_side,
                         do_handshake_on_connect=do_handshake_on_connect,
                         suppress_ragged_eofs=suppress_ragged_eofs,
                         server_hostname=server_hostname,
                         _context=self)


    def set_ciphers(self, ciphers):
        """
        Set the available ciphers for sockets created with this context. It
        should be a string in the wolfSSL cipher list format. If no cipher can
        be selected (because compile-time options or other configuration forbids
        use of all the specified ciphers), an SSLError will be raised.
        """
        ret = _lib.wolfSSL_CTX_set_cipher_list(self.native_object, t2b(ciphers))

        if ret != _SSL_SUCCESS:
            raise SSLError("Unnable to set cipher list")


    def load_cert_chain(self, certfile, keyfile=None, password=None):
        """
        Load a private key and the corresponding certificate. The certfile
        string must be the path to a single file in PEM format containing
        the certificate as well as any number of CA certificates needed to
        establish the certificate's authenticity.

        The keyfile string, if present, must point to a file containing the
        private key in.
        """

        if certfile:
            ret = _lib.wolfSSL_CTX_use_certificate_chain_file(
                self.native_object, t2b(certfile))
            if ret != _SSL_SUCCESS:
                raise SSLError("Unnable to load certificate chain. Err %d"% ret)
        else:
            raise TypeError("certfile should be a valid filesystem path")

        if keyfile:
            ret = _lib.wolfSSL_CTX_use_PrivateKey_file(
                self.native_object, t2b(keyfile), _SSL_FILETYPE_PEM)
            if ret != _SSL_SUCCESS:
                raise SSLError("Unnable to load private key. Err %d" % ret)


    def load_verify_locations(self, cafile=None, capath=None, cadata=None):
        """
        Load a set of "certification authority" (CA) certificates used to
        validate other peers' certificates when verify_mode is other than
        CERT_NONE. At least one of cafile or capath must be specified.

        The cafile string, if present, is the path to a file of concatenated
        CA certificates in PEM format.

        The capath string, if present, is the path to a directory containing
        several CA certificates in PEM format.
        """

        if cafile is None and capath is None and cadata is None:
            raise TypeError("cafile, capath and cadata cannot be all omitted")

        if cafile or capath:
            ret = _lib.wolfSSL_CTX_load_verify_locations(
                self.native_object,
                t2b(cafile) if cafile else _ffi.NULL,
                t2b(capath) if capath else _ffi.NULL)

            if ret != _SSL_SUCCESS:
                raise SSLError("Unnable to load verify locations. Err %d" % ret)

        if cadata:
            ret = _lib.wolfSSL_CTX_load_verify_buffer(
                self.native_object, t2b(cadata), len(cadata), _SSL_FILETYPE_PEM)

            if ret != _SSL_SUCCESS:
                raise SSLError("Unnable to load verify locations. Err %d" % ret)

class SSLSocket(socket):
    """
    This class implements a subtype of socket.socket that wraps the
    underlying OS socket in an SSL context when necessary, and provides
    read and write methods over that channel.
    """

    def __init__(self, sock=None, keyfile=None, certfile=None,
                 server_side=False, cert_reqs=CERT_NONE,
                 ssl_version=PROTOCOL_TLS, ca_certs=None,
                 do_handshake_on_connect=True, family=AF_INET,
                 sock_type=SOCK_STREAM, proto=0, fileno=None,
                 suppress_ragged_eofs=True, ciphers=None,
                 _context=None):
        pass


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
