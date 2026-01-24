# tests/cryptocb-provider/Makefile
#
# Copyright (C) 2006-2025 wolfSSL Inc.
#
# Simple standalone Makefile for building the external crypto provider.
# This compiles wolfcrypt sources directly into the shared library.

# Path to wolfSSL root directory (can be overridden)
WOLFSSL_DIR ?= ../..

# Output library name
LIB_NAME = libcryptocbprovider.so

# Compiler settings
CC ?= gcc

# TODO: Open problem: how to get external CFLAGS when autotool is used
CFLAGS ?=
CFLAGS += -ggdb -O0 -Wall -DWOLFSSL_USER_SETTINGS -fPIC -fvisibility=hidden
CFLAGS += -I. -I$(WOLFSSL_DIR)

# Provider implementation
PROVIDER_SRC = cryptocb_provider.c

# wolfCrypt source files - use wildcard as sources are properly guarded
WOLFCRYPT_SRC = $(wildcard $(WOLFSSL_DIR)/wolfcrypt/src/*.c)

# Filter out evp.c and misc.c
WOLFCRYPT_SRC := $(filter-out $(WOLFSSL_DIR)/wolfcrypt/src/evp.c,$(WOLFCRYPT_SRC))
WOLFCRYPT_SRC := $(filter-out $(WOLFSSL_DIR)/wolfcrypt/src/misc.c,$(WOLFCRYPT_SRC))

# Linker flags
LDFLAGS = -shared

# Link math library if needed
LDLIBS = -lm

# Default target
all: $(LIB_NAME)

$(LIB_NAME): $(PROVIDER_SRC) $(WOLFCRYPT_SRC)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(PROVIDER_SRC) $(WOLFCRYPT_SRC) $(LDLIBS)

clean:
	rm -f $(LIB_NAME)

.PHONY: all clean
