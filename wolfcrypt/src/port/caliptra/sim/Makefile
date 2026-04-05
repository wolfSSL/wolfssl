# Makefile for the Caliptra hw-model test harness
#
# Builds caliptra_test_bin using the hw-model C binding as the mailbox
# transport instead of the software simulator (caliptra_sim.c).
#
# Prerequisites:
#   - wolfSSL must be built in the repo root with --enable-caliptra (or at
#     minimum WOLFSSL_CALIPTRA + WOLF_CRYPTO_CB in CFLAGS).
#   - ~/caliptra/target/debug/libcaliptra_hw_model_c_binding.a must exist
#     (built by: cd ~/caliptra && cargo build -p caliptra-hw-model-c-binding)
#   - ROM and firmware images at the paths below.
#
# Usage:
#   make                     # build
#   make run                 # build and run
#   make clean

# -------------------------------------------------------------------------
# Repository root (three levels up from this Makefile's directory)
# -------------------------------------------------------------------------
WOLFSSL_ROOT ?= $(realpath $(dir $(lastword $(MAKEFILE_LIST)))/../../../../..)

# -------------------------------------------------------------------------
# Caliptra hw-model C binding
# -------------------------------------------------------------------------
CALIPTRA_ROOT    ?= $(HOME)/caliptra
HWMODEL_OUT       = $(CALIPTRA_ROOT)/hw-model/c-binding/out
HWMODEL_LIB_DIR   = $(CALIPTRA_ROOT)/target/debug
HWMODEL_LIB       = $(HWMODEL_LIB_DIR)/libcaliptra_hw_model_c_binding.a

# ROM and firmware images (debug/unprovisioned mode — zero fuses)
ROM_PATH ?= $(CALIPTRA_ROOT)/rom/ci_frozen_rom/2.1/caliptra-rom-2.1.0-a72a76f.bin
FW_PATH  ?= $(HWMODEL_OUT)/image_bundle.bin

# -------------------------------------------------------------------------
# Compiler
# -------------------------------------------------------------------------
CC      ?= gcc
CFLAGS  += -std=c99 -Wall -Wextra -g
CFLAGS  += -DWOLFSSL_CALIPTRA -DWOLF_CRYPTO_CB -DWOLF_CRYPTO_CB_FREE
CFLAGS  += -DCALIPTRA_HWMODEL
# Tell wolfSSL settings.h to include wolfssl/options.h (autoconf feature flags)
CFLAGS  += -DWOLFSSL_USE_OPTIONS_H
# Match the ABI of libwolfssl.a: the library was compiled without -std=c99 so
# GCC defaults to gnu17, which satisfies (__STDC_VERSION__ >= 201101L) and
# therefore defines HAVE_ANONYMOUS_INLINE_AGGREGATES=1 in types.h.  Without
# this define, wc_CryptoInfo uses a sequential (non-union) layout that is
# incompatible with the union layout the library was built with.
CFLAGS  += -DHAVE_ANONYMOUS_INLINE_AGGREGATES=1

# Include paths:
#   1. wolfSSL headers
#   2. hw-model C binding header (caliptra_model.h)
#   3. This directory (caliptra_top_reg.h, caliptra_hwmodel.h)
CFLAGS  += -I$(WOLFSSL_ROOT)
CFLAGS  += -I$(HWMODEL_OUT)
CFLAGS  += -I$(dir $(lastword $(MAKEFILE_LIST)))

# Pass ROM and FW paths to caliptra_test.c via preprocessor defines
CFLAGS  += -DCALIPTRA_ROM_PATH='"$(ROM_PATH)"'
CFLAGS  += -DCALIPTRA_FW_PATH='"$(FW_PATH)"'

# -------------------------------------------------------------------------
# Source files
# -------------------------------------------------------------------------
SIM_DIR  = $(dir $(lastword $(MAKEFILE_LIST)))
PORT_SRC = $(WOLFSSL_ROOT)/wolfcrypt/src/port/caliptra/caliptra_port.c

SRCS     = $(SIM_DIR)caliptra_hwmodel.c \
           $(SIM_DIR)caliptra_test.c    \
           $(PORT_SRC)

OBJS     = $(patsubst %.c,%.o,$(SRCS))

TARGET   = caliptra_test_bin

# -------------------------------------------------------------------------
# Link
# -------------------------------------------------------------------------
WOLFSSL_LIB = $(WOLFSSL_ROOT)/src/.libs/libwolfssl.a

# libcaliptra_hw_model_c_binding.a is a Rust library; needs C++ runtime,
# pthreads, and system libraries.
LDFLAGS  = $(WOLFSSL_LIB)
LDFLAGS += $(HWMODEL_LIB)
LDFLAGS += -lpthread -lstdc++ -ldl -lrt -lm

# -------------------------------------------------------------------------
# Rules
# -------------------------------------------------------------------------
.PHONY: all run clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)
