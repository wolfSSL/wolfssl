 #
 # Copyright (C) 2006-2019 wolfSSL Inc.
 #
 # This file is part of wolfSSL.
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
 # Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
 #


NAME := wolfssl_https_client

USE_WOLFSSL = 1

# If you want to verify certificates turn on
VERIFY_CERTIFICATE = 1
# wolfSSL provides the option to load a single certificate or a chain.
# this application shows the functionality of using a chain buffer.
# If you want to see other options, refer to www.wolfssl.com/docs for further
# API functions involving the use of certificate verification. You may further
# configure these APIs in the file wiced_tls.c for use with PEM or DER certificates.
# Turn on if you are using a chain and turn off if you are using a single cert.
USE_CHAIN_BUFFER = 1
STATIC_CA = 1
WOLF_SERVER = 0
USE_TLSv13 = 1

GLOBAL_DEFINES += WICED_CONFIG_DISABLE_DTLS

ifeq (0, ${VERIFY_CERTIFICATE})
	GLOBAL_DEFINES     += WOLFSSL_WICED_NO_VERIFY_CERTIFICATE
else
ifeq (1, ${USE_CHAIN_BUFFER})
	GLOBAL_DEFINES     += WOLFSSL_WICED_LOAD_VERIFY_CHAIN_BUFFER
else
	GLOBAL_DEFINES     += WOLFSSL_WICED_LOAD_VERIFY_BUFFER
endif
endif

ifeq (1, ${WOLF_SERVER})
	GLOBAL_DEFINES    += USE_WOLF_SERVER
endif
ifeq (1, ${STATIC_CA})
	GLOBAL_DEFINES    += WOLF_STATIC_CA
endif
ifeq (1, ${USE_TLSv13})
	GLOBAL_DEFINES    += TLSv13
endif

GLOBAL_DEFINES     += APPLICATION_STACK_SIZE=1024*64   \
					  WOLFSSL_USER_SETTINGS   \
					  WOLFSSL_WICED  \
					  WOLFSSL_NO_SERVER

GLOBAL_INCLUDES += WICED/security/BESL/wolfssl_lib  \
GLOBAL_INCLUDES +=  wolfssl \
					wolfssl/wolfcrypt


$(NAME)_SOURCES    := wolfssl_https_client.c

$(NAME)_COMPONENTS := protocols/HTTP_client
