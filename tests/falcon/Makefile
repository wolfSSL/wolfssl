# tests/falcon/Makefile -- builds the Falcon keygen/sign/verify fuzzer.
#
# Standalone:  cd tests/falcon && make           (links the in-tree library)
#              cd tests/falcon && make run        (build + short smoke run)
#
# Assumes the parent wolfSSL tree has been configured and built with
#   ./configure --enable-experimental --enable-falcon && make
# so that src/.libs/libwolfssl.so and wolfssl/options.h exist.

SRCDIR   ?= $(CURDIR)
WOLFROOT ?= $(abspath $(SRCDIR)/../..)

CC       ?= cc
CFLAGS   ?= -Wall -Wextra -O2
# The fuzzer includes <wolfssl/options.h> directly (autotools build), so do
# NOT define WOLFSSL_USER_SETTINGS here.
CPPFLAGS += -I$(WOLFROOT)
# Link against the freshly built in-tree library, not any system copy.
LDFLAGS  += -L$(WOLFROOT)/src/.libs
LDLIBS   += -lwolfssl

# Let the loader find the in-tree shared object at run time without an install.
export LD_LIBRARY_PATH := $(WOLFROOT)/src/.libs:$(LD_LIBRARY_PATH)

BIN = falcon_fuzz

.PHONY: all run clean

all: $(BIN)

$(BIN): falcon_fuzz.c $(WOLFROOT)/wolfssl/options.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

$(WOLFROOT)/wolfssl/options.h:
	@echo "error: $(WOLFROOT) is not configured/built." >&2
	@echo "  run:  cd $(WOLFROOT) && ./configure --enable-experimental \
--enable-falcon && make" >&2
	@false

# Short run suitable for a quick check; the CI wrapper (run.sh) uses a longer one.
run: $(BIN)
	./$(BIN) --iters 200 --msgs 4

clean:
	rm -f $(BIN) *.repro
