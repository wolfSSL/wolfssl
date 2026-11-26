# wolfCrypt CRACEN test for the nRF54L15 DK, bare metal with GCC.
#
#   make deps    fetch the nrfx MDK/HAL, the CMSIS core headers and the PK
#                engine microcode (once)
#   make         build build/wolfcrypt_cracen_test.{elf,hex}
#   make flash   program the DK with nrfutil and reset it
#
# See README.md.

WOLFSSL_ROOT ?= ../../..
BUILD_DIR    ?= build
BIN          ?= wolfcrypt_cracen_test

DEPS_DIR  ?= deps
NRFX_DIR  ?= $(DEPS_DIR)/nrfx
CMSIS_DIR ?= $(DEPS_DIR)/cmsis
NRFX_TAG  ?= v3.14.0
CMSIS_TAG ?= 5.9.0

# PK engine microcode (ba414ep_ucode), fetched from the nRF Connect SDK at a
# pinned commit. LicenseRef-Nordic-5-Clause: it is not part of wolfSSL and is
# never copied into the tree. Without the file the build still runs, with the
# public key algorithms in software.
SDK_NRF_REF   ?= 146ad6cc74d0ab962bd1f2bb32eb385549a63f0a
MICROCODE_H    = $(DEPS_DIR)/cracen_microcode.h
MICROCODE_URL  = https://raw.githubusercontent.com/nrfconnect/sdk-nrf/$(SDK_NRF_REF)/subsys/nrf_security/src/drivers/cracen/common/src/cracen/hardware/microcode_binary.h

TOOLCHAIN ?= arm-none-eabi-
CC      = $(TOOLCHAIN)gcc
OBJCOPY = $(TOOLCHAIN)objcopy
SIZE    = $(TOOLCHAIN)size

ARCHFLAGS = -mcpu=cortex-m33 -mthumb -mfloat-abi=soft

# Bytes of raw TRNG output to print as hex after the tests (0 = none)
TRNG_DUMP ?= 0

# 1: keep the chip's automatic reset on a CRACEN tamper event; 0: turn it off
# in TAMPC at start-up so a PK engine misuse is reported instead of resetting
TAMPER_RESET ?= 1

# __STACK_SIZE / __HEAP_SIZE size the .stack/.heap sections in the MDK startup.
# NRF_SKIP_SAU_CONFIGURATION keeps the SAU off, so the whole address map stays
# secure: the MDK default would mark RRAM at 0x0 and RAM at 0x20000000, where
# this image lives, non-secure.
DEFS = -DNRF54L15_XXAA -DNRF_APPLICATION -DWOLFSSL_USER_SETTINGS \
       -DNRF_SKIP_SAU_CONFIGURATION \
       -D__STACK_SIZE=0x8000 -D__HEAP_SIZE=0x2C000 \
       -DCRACEN_TRNG_DUMP=$(TRNG_DUMP) -DCRACEN_TAMPER_RESET=$(TAMPER_RESET)
ifneq ($(wildcard $(MICROCODE_H)),)
DEFS += -DCRACEN_HAVE_MICROCODE
endif

INC  = -I. \
       -I$(WOLFSSL_ROOT) \
       -I$(DEPS_DIR) \
       -I$(NRFX_DIR) \
       -I$(NRFX_DIR)/mdk \
       -I$(NRFX_DIR)/templates \
       -I$(NRFX_DIR)/drivers/include \
       -I$(CMSIS_DIR)/CMSIS/Core/Include

# -mcmse marks this as the secure image: the MDK's SystemInit then applies the
# device trims and errata, configures the SAU and opens the debug access port
# (without it the port stays locked after every reset)
CFLAGS  = $(ARCHFLAGS) -mcmse $(DEFS) $(INC) -std=gnu99 -Wall -Wextra \
          -Wno-unused-parameter -Os -g -ffunction-sections -fdata-sections \
          -fno-builtin -MMD -MP $(CFLAGS_EXTRA)
ASFLAGS = $(ARCHFLAGS) $(DEFS)
LDFLAGS = $(ARCHFLAGS) --specs=nano.specs --specs=nosys.specs \
          -Wl,--gc-sections -T linker.ld -L $(NRFX_DIR)/mdk \
          -Wl,-Map=$(BUILD_DIR)/$(BIN).map

# Application
SRC_C  = src/main.c src/board.c
# Nordic MDK system init
SRC_C += $(NRFX_DIR)/mdk/system_nrf54l.c
# wolfCrypt test suite
SRC_C += $(WOLFSSL_ROOT)/wolfcrypt/test/test.c
# wolfCrypt; misc.c and evp.c are #included by other files
SRC_C += $(filter-out %/misc.c %/evp.c, $(wildcard $(WOLFSSL_ROOT)/wolfcrypt/src/*.c))
# the CRACEN port
SRC_C += $(wildcard $(WOLFSSL_ROOT)/wolfcrypt/src/port/nordic/*.c)

SRC_S  = $(NRFX_DIR)/mdk/gcc_startup_nrf54l15_application.S

OBJS  = $(addprefix $(BUILD_DIR)/, $(notdir $(SRC_C:.c=.o)))
OBJS += $(addprefix $(BUILD_DIR)/, $(notdir $(SRC_S:.S=.o)))

vpath %.c $(sort $(dir $(SRC_C)))
vpath %.S $(sort $(dir $(SRC_S)))

.PHONY: all deps flash clean distclean

all: $(BUILD_DIR)/$(BIN).hex

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) -c -o $@ $<

$(BUILD_DIR)/%.o: %.S | $(BUILD_DIR)
	$(CC) $(ASFLAGS) -c -o $@ $<

$(BUILD_DIR)/$(BIN).elf: $(OBJS) linker.ld
	$(CC) $(LDFLAGS) -o $@ $(OBJS) -lm
	$(SIZE) $@

$(BUILD_DIR)/$(BIN).hex: $(BUILD_DIR)/$(BIN).elf
	$(OBJCOPY) -O ihex $< $@

# header dependencies recorded by -MMD, so a user_settings.h change rebuilds
-include $(OBJS:.o=.d)

# Sparse checkouts: only the directories this build reads.
deps:
	@mkdir -p "$(DEPS_DIR)"
	@if [ ! -f "$(MICROCODE_H)" ]; then \
	    curl -fsSL -o "$(MICROCODE_H)" "$(MICROCODE_URL)" || \
	        { rm -f "$(MICROCODE_H)"; \
	          echo "microcode not fetched: public key tests run in software"; }; \
	fi
	@if [ ! -d "$(NRFX_DIR)/mdk" ]; then \
	    rm -rf "$(NRFX_DIR)"; \
	    git clone --depth 1 --branch $(NRFX_TAG) --filter=blob:none --no-checkout \
	        https://github.com/NordicSemiconductor/nrfx.git "$(NRFX_DIR)" && \
	    cd "$(NRFX_DIR)" && git sparse-checkout init --cone && \
	    git sparse-checkout set mdk hal haly helpers templates soc drivers/include && \
	    git checkout -q && git checkout -q HEAD -- nrfx.h drivers; \
	fi
	@if [ ! -d "$(CMSIS_DIR)/CMSIS/Core/Include" ]; then \
	    rm -rf "$(CMSIS_DIR)"; \
	    git clone --depth 1 --branch $(CMSIS_TAG) --filter=blob:none --no-checkout \
	        https://github.com/ARM-software/CMSIS_5.git "$(CMSIS_DIR)" && \
	    cd "$(CMSIS_DIR)" && git sparse-checkout init --cone && \
	    git sparse-checkout set CMSIS/Core/Include && git checkout -q; \
	fi

flash: $(BUILD_DIR)/$(BIN).hex
	nrfutil device program --firmware $< --options chip_erase_mode=ERASE_ALL,reset=RESET_SYSTEM

clean:
	rm -rf $(BUILD_DIR)

distclean: clean
	rm -rf $(DEPS_DIR)
