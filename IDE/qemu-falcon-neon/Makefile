CC := aarch64-none-elf-gcc
OBJCOPY := aarch64-none-elf-objcopy
OBJDUMP := aarch64-none-elf-objdump

CFLAGS := -O2 -ffreestanding -fno-stack-protector -g
CFLAGS += -fdata-sections -ffunction-sections -Wall -Wextra
CFLAGS += -I. -I../.. -DWOLFSSL_USER_SETTINGS

CFLAGS_WOLFSSL := $(CFLAGS) -Wno-unused-function -Wno-unused-variable

LDFLAGS := -T link.ld -nostartfiles --specs=nosys.specs -Wl,-gc-sections -lm

APP_SRCS := main.c
ASM_SRCS := start.S

# Full native Falcon (keygen + sign + verify) + SHAKE256 + runtime.
WOLFSSL_SRCS := \
	../../wolfcrypt/src/falcon.c \
	../../wolfcrypt/src/wc_falcon.c \
	../../wolfcrypt/src/wc_falcon_fpr.c \
	../../wolfcrypt/src/wc_falcon_fft.c \
	../../wolfcrypt/src/wc_falcon_fft_neon.c \
	../../wolfcrypt/src/wc_falcon_poly.c \
	../../wolfcrypt/src/wc_falcon_sampler.c \
	../../wolfcrypt/src/wc_falcon_codec.c \
	../../wolfcrypt/src/wc_falcon_keygen.c \
	../../wolfcrypt/src/wc_falcon_sign.c \
	../../wolfcrypt/src/wc_falcon_bigint.c \
	../../wolfcrypt/src/sha3.c \
	../../wolfcrypt/src/sha256.c \
	../../wolfcrypt/src/hash.c \
	../../wolfcrypt/src/memory.c \
	../../wolfcrypt/src/random.c \
	../../wolfcrypt/src/wc_port.c \
	../../wolfcrypt/src/wolfmath.c

APP_OBJS := $(patsubst %.c,build/%.o,$(APP_SRCS)) $(patsubst %.S,build/%.o,$(ASM_SRCS))
WOLFSSL_OBJS := $(patsubst ../../%.c,build/%.o,$(WOLFSSL_SRCS))
OBJS := $(APP_OBJS) $(WOLFSSL_OBJS)

all: app-falcon-neon.elf

app-falcon-neon.elf: $(OBJS) link.ld
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $@

build/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

build/%.o: %.S
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

build/wolfcrypt/src/%.o: ../../wolfcrypt/src/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS_WOLFSSL) -c $< -o $@

dis: app-falcon-neon.elf
	$(OBJDUMP) -d app-falcon-neon.elf > app-falcon-neon.dis

clean:
	rm -rf build app-falcon-neon.elf app-falcon-neon.dis

.PHONY: all dis clean
