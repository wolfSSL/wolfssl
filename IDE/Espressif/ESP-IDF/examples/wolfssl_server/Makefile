# ESP8266 Project Makefile for wolfssl_client
#
# Copyright (C) 2006-2025 wolfSSL Inc.
#
# This file is part of wolfSSL.
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
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

PROJECT_NAME := wolfssl_server

$(info *************  wolfssl_server main project  *************)

# ------------- BEGIN COMMON SECTION -------------
ifeq ($(strip $(WOLFSSL_ROOT)),)
    $(info Initial WOLFSSL_ROOT is blank, component will search parent directories)
else
    $(info Found WOLFSSL_ROOT = $(WOLFSSL_ROOT))
    $(info Checking if WOLFSSL_ROOT is anywhere in current path parent)
    WOLFSSL_ROOT_ABS     := $(abspath $(WOLFSSL_ROOT))
    CURDIR_ABS           := $(abspath $(CURDIR))

    # Ensure trailing slashes stripped once, then re-add exactly one
    ROOT_NOSLASH := $(patsubst %/,%,$(WOLFSSL_ROOT_ABS))
    CUR_NOSLASH  := $(patsubst %/,%,$(CURDIR_ABS))
    THIS_ROOT    := $(ROOT_NOSLASH)/
    THIS_CDIR    := $(CUR_NOSLASH)/

    $(info THIS_ROOT = $(THIS_ROOT))
    $(info THIS_CDIR  = $(THIS_CDIR))

    ifeq ($(wildcard $(WOLFSSL_ROOT_ABS)),)
        $(error Directory does NOT exist: $(WOLFSSL_ROOT_ABS))
    else
        $(info Confirmed directory exists: $(WOLFSSL_ROOT_ABS))
    endif

    ifneq (,$(filter $(THIS_ROOT)%,$(THIS_CDIR)))
      $(info WOLFSSL_ROOT ($(WOLFSSL_ROOT_ABS)) is in the parent tree of $(CURDIR_ABS))
    else
      $(warning WOLFSSL_ROOT ($(WOLFSSL_ROOT_ABS)) is NOT in the parent tree of $(CURDIR_ABS))
    endif
endif

ifeq ($(strip $(IDF_PATH)),)
  $(error IDF_PATH is not set. Please export it before running make)
endif

# Default compiler flags
CFLAGS   ?=
CXXFLAGS ?=

CFLAGS += -DWOLFSSL_USER_SETTINGS

# Some of the tests are CPU intenstive, so we'll force the watchdog timer off.
# There's an espressif NO_WATCHDOG; we don't use it, as it is reset by sdkconfig.
CFLAGS += -DWOLFSSL_ESP_NO_WATCHDOG=1

# Check if CONFIG_WOLFSSL_USE_MY_PRIVATE_CONFIG is set to 1 in environment
ifeq ($(CONFIG_WOLFSSL_USE_MY_PRIVATE_CONFIG),1)
    $(info Setting CONFIG_WOLFSSL_USE_MY_PRIVATE_CONFIG from environment variable for Makefile)
    CFLAGS   += -DCONFIG_WOLFSSL_USE_MY_PRIVATE_CONFIG=1
    CXXFLAGS += -DCONFIG_WOLFSSL_USE_MY_PRIVATE_CONFIG=1
else
    $(info CONFIG_WOLFSSL_USE_MY_PRIVATE_CONFIG not set, not using private config.)
endif

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

# Optionally include component source when print path (needs work to then properly build)
#
# include components/wolfssl/component.mk

MY_PRIVATE_CONFIG             ?= n
USE_MY_PRIVATE_WSL_CONFIG     ?= n
USE_MY_PRIVATE_MAC_CONFIG     ?= n
USE_MY_PRIVATE_LINUX_CONFIG   ?= n
USE_MY_PRIVATE_WINDOWS_CONFIG ?= n

# Calling shell causes unintuitive error in Windows:
#     OS := $(shell uname -s)
#
# But OS, or MY_PRIVATE_CONFIG should already be defined:

ifeq ($(MY_PRIVATE_CONFIG),y)
	CFLAGS += -DMY_PRIVATE_CONFIG
	$(info Enabled MY_PRIVATE_CONFIG)
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
	MY_CONFIG_FILE := $(HOME)/workspace/my_private_config.h
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
	MY_CONFIG_FILE := $(HOME)/Documents/my_private_config.h
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

# if there isn't the directory, please disable the line below.
EXTRA_COMPONENT_DIRS = $(IDF_PATH)/examples/common_components/protocol_examples_common

# The Standard Espressif IDF include:
include $(IDF_PATH)/make/project.mk

$(info ************* end wolfssl_server main project  *************)
