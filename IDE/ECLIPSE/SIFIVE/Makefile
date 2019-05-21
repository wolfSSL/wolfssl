PROGRAM ?= wolfcrypt

# This line must be added in your freedom-e-sdk/scripts/standalone.mk
# RISCV_CFLAGS   += -I$(WOLFSSL_SRC_DIR) -I$(WOLFSSL_SRC_DIR)/IDE/ECLIPSE/SIFIVE -DWOLFSSL_USER_SETTINGS
# WOLFSSL_SRC_DIR variable must be set in the environment when GNU make is started.

WOLFSSL_CFLAGS += -I$(WOLFSSL_SRC_DIR) \
				  -I$(WOLFSSL_SRC_DIR)/IDE/ECLIPSE/SIFIVE \
				  -DWOLFSSL_USER_SETTINGS

SRC_FILES  = $(wildcard $(WOLFSSL_SRC_DIR)/src/*.c)
SRC_FILES += $(wildcard $(WOLFSSL_SRC_DIR)/wolfcrypt/src/*.c)
SRC_FILES := $(filter-out %bio.c %misc.c %evp.c, $(SRC_FILES))

SRC =$(WOLFSSL_SRC_DIR)/IDE/ECLIPSE/SIFIVE/main.c \
	 $(SRC_FILES) \
	 $(WOLFSSL_SRC_DIR)/wolfcrypt/test/test.c \
	 $(WOLFSSL_SRC_DIR)/wolfcrypt/benchmark/benchmark.c

OPT_CFLAGS = -specs=nano.specs
#OPT_CFLAGS += -O3 -DTIME -DNOENUM -Wno-implicit -mexplicit-relocs -save-temps
#OPT_CFLAGS += -fno-inline -fno-builtin-printf -fno-common -falign-functions=4

override CFLAGS += $(OPT_CFLAGS) $(WOLFSSL_CFLAGS) \
                     -Xlinker --defsym=__stack_size=0x1000

$(PROGRAM): $(SRC)
	$(CC) $(CFLAGS) $(SRC) $(LDFLAGS) $(LDLIBS) -o $@

clean:
	rm -f $(PROGRAM) $(PROGRAM).hex
