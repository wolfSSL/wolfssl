#
#  Copyright (C) 2014-2022 wolfSSL Inc.
#
# This file is part of wolfSSH.
#
# wolfSSH is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfSSH is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with wolfSSH.  If not, see <http://www.gnu.org/licenses/>.
#
#
# Component Makefile
#

COMPONENT_ADD_INCLUDEDIRS := . ./include

COMPONENT_ADD_INCLUDEDIRS += "$ENV{IDF_PATH}/components/freertos/include/freertos"
# COMPONENT_ADD_INCLUDEDIRS += "$ENV{IDF_PATH}/soc/esp32s3/include/soc"

COMPONENT_SRCDIRS := src wolfcrypt/src
COMPONENT_SRCDIRS += wolfcrypt/src/port/Espressif
COMPONENT_SRCDIRS += wolfcrypt/src/port/atmel

CFLAGS +=-DWOLFSSL_USER_SETTINGS

COMPONENT_OBJEXCLUDE := wolfcrypt/src/aes_asm.o
COMPONENT_OBJEXCLUDE += wolfcrypt/src/evp.o
COMPONENT_OBJEXCLUDE += wolfcrypt/src/misc.o
COMPONENT_OBJEXCLUDE += src/bio.o
