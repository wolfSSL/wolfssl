# wolfCrypt CRACEN test for the nRF54L15 DK, bare metal with GCC.
#
#   make deps    fetch the nrfx MDK/HAL and the CMSIS core headers (once)
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

TOOLCHAIN ?= arm-none-eabi-
CC      = $(TOOLCHAIN)gcc
OBJCOPY = $(TOOLCHAIN)objcopy
SIZE    = $(TOOLCHAIN)size

ARCHFLAGS = -mcpu=cortex-m33 -mthumb -mfloat-abi=soft

# Bytes of raw TRNG output to print as hex after the tests (0 = none)
TRNG_DUMP ?= 0

# __STACK_SIZE / __HEAP_SIZE size the .stack/.heap sections in the MDK startup
DEFS = -DNRF54L15_XXAA -DNRF_APPLICATION -DWOLFSSL_USER_SETTINGS \
       -D__STACK_SIZE=0x8000 -D__HEAP_SIZE=0x18000 \
       -DCRACEN_TRNG_DUMP=$(TRNG_DUMP)

INC  = -I. \
       -I$(WOLFSSL_ROOT) \
       -I$(NRFX_DIR) \
       -I$(NRFX_DIR)/mdk \
       -I$(NRFX_DIR)/templates \
       -I$(NRFX_DIR)/drivers/include \
       -I$(CMSIS_DIR)/CMSIS/Core/Include

CFLAGS  = $(ARCHFLAGS) $(DEFS) $(INC) -std=gnu99 -Wall -Wextra -Wno-unused-parameter \
          -Os -g -ffunction-sections -fdata-sections -fno-builtin $(CFLAGS_EXTRA)
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

# Sparse checkouts: only the directories this build reads.
deps:
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
