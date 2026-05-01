# Build the emNET non-blocking handshake test.
# Requires wolfSSL already configured + built at the repo root with
# WOLFSSL_EMNET and the emnet IP include path, e.g.:
#
#   cd $(repo_root)
#   ./autogen.sh
#   ./configure --enable-static --disable-shared --enable-tls13 \
#               --disable-oldtls CFLAGS="-DWOLFSSL_EMNET \
#               -I$$(pwd)/tests/emnet"
#   make
#   make -C tests/emnet run
#
# recv/send fall through to glibc's POSIX implementation (-1 + errno
# on would-block); wolfSSL_LastError then retrieves the canonical
# IP_ERR_* via IP_SOCK_getsockopt in the shim. This is the integrator
# convention that reproduces ticket #21673 and the one wolfSSL's
# WOLFSSL_EMNET error path must handle correctly.

CURDIR     := $(shell pwd)
WOLFSSL_ROOT := $(abspath $(CURDIR)/../..)
WOLFSSL_LIB := $(WOLFSSL_ROOT)/src/.libs/libwolfssl.a

CC ?= cc
CFLAGS_TEST := -Wall -Wextra -O2 -g \
    -DWOLFSSL_EMNET \
    -I$(CURDIR) \
    -I$(WOLFSSL_ROOT)
LIBS_TEST := $(WOLFSSL_LIB) -lpthread -lm

TEST_BIN := emnet_nonblock_test

.PHONY: all run clean check-lib

all: $(TEST_BIN)

check-lib:
	@if [ ! -f "$(WOLFSSL_LIB)" ]; then \
	    echo "error: $(WOLFSSL_LIB) not found."; \
	    echo "Build wolfSSL first (see header of this Makefile)."; \
	    exit 1; \
	fi

# check-lib is an order-only dependency (after |) so its phony status
# does not force the binary to relink on every `make` invocation.
$(TEST_BIN): emnet_nonblock_test.o emnet_shim.o | check-lib
	$(CC) -o $@ emnet_nonblock_test.o emnet_shim.o $(LIBS_TEST)

emnet_nonblock_test.o: emnet_nonblock_test.c
	$(CC) $(CFLAGS_TEST) -c $< -o $@

emnet_shim.o: emnet_shim.c IP/IP.h
	$(CC) $(CFLAGS_TEST) -c $< -o $@

# Run from the repo root so the relative cert paths resolve.
run: $(TEST_BIN)
	cd $(WOLFSSL_ROOT) && ./tests/emnet/$(TEST_BIN)

clean:
	rm -f *.o $(TEST_BIN)
