# _context.py
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
try:
    from wolfssl._ffi  import ffi as _ffi
    from wolfssl._ffi  import lib as _lib
except ImportError:
    pass

from wolfssl._methods import WolfSSLMethod
from wolfssl._exceptions import *

CERT_NONE     = 0
CERT_OPTIONAL = 1
CERT_REQUIRED = 2

_SSL_FILETYPE_PEM = 1

class SSLContext:
    """An SSLContext holds various SSL-related configuration options and
    data, such as certificates and possibly a private key."""


    def __init__(self, protocol, server_side=False):
        method = WolfSSLMethod(protocol, server_side)
        
        self.protocol      = protocol
        self._side         = server_side
        self.native_object = _lib.wolfSSL_CTX_new(method.native_object)
        
        # wolfSSL_CTX_new() takes ownership of the method.
        # the method is freed later inside wolfSSL_CTX_free()
        # or if wolfSSL_CTX_new() failed to allocate the context object.
        method.native_object = None

        if self.native_object == _ffi.NULL:
            raise MemoryError("Unnable to allocate context object")


    def __del__(self):
        if self.native_object is not None:
            _lib.wolfSSL_CTX_free(self.native_object)


#    def wrap_socket(self, sock, server_side=False,
#                    do_handshake_on_connect=True,
#                    suppress_ragged_eofs=True,
#                    server_hostname=None):
#        return SSLSocket(sock=sock, server_side=server_side,
#                         do_handshake_on_connect=do_handshake_on_connect,
#                         suppress_ragged_eofs=suppress_ragged_eofs,
#                         server_hostname=server_hostname,
#                         _context=self)
#
#
    def load_cert_chain(self, certfile, keyfile=None, password=None):
        if certfile:
            ret = _lib.wolfSSL_CTX_use_certificate_chain_file(
                self.native_object, certfile)
            if ret != 0:
                raise SSLError("Unnable to load certificate chain")
        else:
            raise TypeError(
                "certfile needs to be string or buffer, NoneType found")

        if keyfile:
            ret = _lib.wolfSSL_CTX_use_PrivateKey_file(
                self.native_object, keyfile, _SSL_FILETYPE_PEM)
            if ret != 0:
                raise SSLError("Unnable to load private key")


    def load_verify_locations(self, cafile=None, capath=None, cadata=None):
        if cafile is None and capath is None:
            raise SSLError("Unnable to load verify locations")

        ret = _lib.wolfSSL_CTX_load_verify_locations(
            self.native_object,
            cafile if cafile else _ffi.NULL,
            capath if capath else _ffi.NULL)

        if ret != 0:
            raise SSLError("Unnable to load verify locations")
