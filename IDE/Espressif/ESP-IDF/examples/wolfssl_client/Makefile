# ESP8266 Project Makefile for wolfssl_client
#
# Copyright (C) 2006-2024 wolfSSL Inc.
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

#
# This is a project Makefile.
# It is assumed the directory this Makefile resides in is a
# project subdirectory containing an entire project.
#
# Optional private config headers. Define environment variables
# to include various default header files that are typically
# not in a git path, and thus excluded from being checked in.
#
#     Environment Variable Name      |     Header file name included
# ---------------------------------- | ---------------------------------------
#    MY_PRIVATE_CONFIG                  (files detected / selected in header)
#    USE_MY_PRIVATE_WSL_CONFIG          /mnt/c/workspace/my_private_config.h
#    USE_MY_PRIVATE_MAC_CONFIG          ~/Documents/my_private_config.h
#    USE_MY_PRIVATE_LINUX_CONFIG        ~/workspace/my_private_config.h
#    USE_MY_PRIVATE_WINDOWS_CONFIG      /workspace/my_private_config.h
#
#
PROJECT_NAME := wolfssl_client

# Optionally include component source when print path (needs work to then properly build)
#
# include components/wolfssl/component.mk

MY_PRIVATE_CONFIG ?= n
USE_MY_PRIVATE_WSL_CONFIG ?= n
USE_MY_PRIVATE_MAC_CONFIG ?= n
USE_MY_PRIVATE_LINUX_CONFIG ?= n
USE_MY_PRIVATE_WINDOWS_CONFIG ?= n

# Calling shell causes unintuitive error in Windows:
#     OS := $(shell uname -s)
#
# But OS, or MY_PRIVATE_CONFIG should already be defined:
$(info *************  wolfssl_client *************)

ifeq ($(MY_PRIVATE_CONFIG),y)
	CFLAGS += -DMY_PRIVATE_CONFIG
	$(info Enabled MY_PRIVATE_CONFIG")
endif

# Check for Windows environment variable: USE_MY_PRIVATE_WINDOWS_CONFIG
ifeq ($(USE_MY_PRIVATE_WINDOWS_CONFIG),y)
	# This hard coded MY_CONFIG_FILE value must match that in the header file.
	MY_CONFIG_FILE := /workspace/my_private_config.h
	ifeq ($(wildcard $(MY_CONFIG_FILE)),)
		$(info File does not exist: $(MY_CONFIG_FILE))
	else
		CFLAGS += -DUSE_MY_PRIVATE_WINDOWS_CONFIG
		$(info Using private config file for: Windows)
	endif
endif

# Check for WSL environment variable: USE_MY_PRIVATE_WSL_CONFIG
ifeq ($(USE_MY_PRIVATE_WSL_CONFIG),y)
	# This hard coded MY_CONFIG_FILE value must match that in the header file.
	MY_CONFIG_FILE := /mnt/c/workspace/my_private_config.h
	ifeq ($(wildcard $(MY_CONFIG_FILE)),)
		$(info File does not exist: $(MY_CONFIG_FILE))
	else
		CFLAGS += -DUSE_MY_PRIVATE_WSL_CONFIG
		$(info Using private config file for: WSL)
	endif
endif

# Check for Linux environment variable: USE_MY_PRIVATE_LINUX_CONFIG
ifeq ($(USE_MY_PRIVATE_LINUX_CONFIG),y)
	# This hard coded MY_CONFIG_FILE value must match that in the header file.
	MY_CONFIG_FILE := ~/workspace/my_private_config.h
	ifeq ($(wildcard $(MY_CONFIG_FILE)),)
		$(info File does not exist: $(MY_CONFIG_FILE))
	else
		CFLAGS += -DUSE_MY_PRIVATE_LINUX_CONFIG
		$(info Using private config file for: Linux)
	endif
endif

# Check for Mac environment variable: USE_MY_PRIVATE_MAC_CONFIG
ifeq ($(USE_MY_PRIVATE_MAC_CONFIG),y)
	# This hard coded MY_CONFIG_FILE value must match that in the header file.
	MY_CONFIG_FILE := ~/Documents/my_private_config.h
	ifeq ($(wildcard $(MY_CONFIG_FILE)),)
		$(info File does not exist: $(MY_CONFIG_FILE))
	else
		CFLAGS += -DUSE_MY_PRIVATE_MAC_CONFIG
		$(info Using private config file for: Mac)
	endif
endif

ifneq ($(OS),MY_PRIVATE_CONFIG)
	CFLAGS += -DMY_PRIVATE_CONFIG="$(MY_PRIVATE_CONFIG)"
else
	ifeq ($(OS),Linux)
		CFLAGS += -DOS_LINUX
	endif
	ifeq ($(OS),Windows_NT)
		CFLAGS += -DWOLFSSL_MAKE_SYSTEM_NAME_WINDOWS
	endif
	ifeq ($(OS),Darwin)
		CFLAGS += -DWOLFSSL_MAKE_SYSTEM_NAME_APPLE
	endif
	ifneq (,$(findstring MINGW,$(OS)))
		CFLAGS += -DWOLFSSL_MAKE_SYSTEM_NAME_MINGW
	endif
	ifneq (,$(findstring CYGWIN,$(OS)))
		CFLAGS += -DWOLFSSL_MAKE_SYSTEM_NAME_CYGWIN
	endif
endif

# It is essential that the build process sees the WOLFSSL_USER_SETTINGS
CFLAGS += -DWOLFSSL_USER_SETTINGS

# if directory not available, please disable the line below.
EXTRA_COMPONENT_DIRS = $(IDF_PATH)/examples/common_components/protocol_examples_common

# The Standard Espressif IDF include:
include $(IDF_PATH)/make/project.mk

