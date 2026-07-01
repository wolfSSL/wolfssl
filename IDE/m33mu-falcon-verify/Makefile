CC := arm-none-eabi-gcc
OBJCOPY ?= arm-none-eabi-objcopy
NM ?= arm-none-eabi-nm
OBJDUMP ?= arm-none-eabi-objdump

CFLAGS := -mcpu=cortex-m33 -mthumb -Os -ffreestanding
CFLAGS += -fdata-sections -ffunction-sections -g -ggdb -Wall -Wextra -Werror
CFLAGS += -I. -I../.. -DWOLFSSL_USER_SETTINGS

CFLAGS_WOLFSSL := $(CFLAGS)
CFLAGS_WOLFSSL := $(filter-out -Werror,$(CFLAGS_WOLFSSL))
CFLAGS_WOLFSSL += -Wno-unused-function -Wno-unused-variable

LDFLAGS := -nostdlib -T target.ld -Wl,-gc-sections

APP_SRCS := main.c ivt.c syscalls.c

# Native Falcon verify path: public wrapper + core (NTT/hash-to-point/codec) +
# SHAKE256, plus the minimal runtime (memory, wc_port).
WOLFSSL_SRCS := \
	../../wolfcrypt/src/falcon.c \
	../../wolfcrypt/src/wc_falcon.c \
	../../wolfcrypt/src/sha3.c \
	../../wolfcrypt/src/sha256.c \
	../../wolfcrypt/src/hash.c \
	../../wolfcrypt/src/memory.c \
	../../wolfcrypt/src/wc_port.c \
	../../wolfcrypt/src/wolfmath.c

APP_OBJS := $(patsubst %.c,build/%.o,$(APP_SRCS))
WOLFSSL_OBJS := $(patsubst ../../%.c,build/%.o,$(WOLFSSL_SRCS))
OBJS := $(APP_OBJS) $(WOLFSSL_OBJS)

all: app-falcon.bin

app-falcon.elf: $(OBJS) target.ld
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) \
		-Wl,--start-group -lc -lm -lgcc -lnosys -Wl,--end-group -o $@

app-falcon.bin: app-falcon.elf
	$(OBJCOPY) -O binary $< $@

build/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

build/wolfcrypt/src/%.o: ../../wolfcrypt/src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_WOLFSSL) -c $< -o $@

symbols: app-falcon.elf
	$(NM) -n app-falcon.elf > app-falcon.sym
	$(OBJDUMP) -d app-falcon.elf > app-falcon.dis

clean:
	rm -rf build app-falcon.elf app-falcon.bin app-falcon.sym app-falcon.dis

.PHONY: all symbols clean
