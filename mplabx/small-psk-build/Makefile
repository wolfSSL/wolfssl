# Set to @ if you want to suppress command echo
CMD_ECHO =

# Important directories
BUILD_DIR = ./Build

# Toolchain location and prefix
TOOLCHAIN ?=

# Tools selection
CC = $(TOOLCHAIN)gcc
AS = $(CC)
LD = $(CC)
AR = $(TOOLCHAIN)ar
NM = $(TOOLCHAIN)nm
OBJCOPY ?= $(TOOLCHAIN)objcopy
OBJDUMP ?= $(TOOLCHAIN)objdump
SIZE ?= $(TOOLCHAIN)size

# Includes
USER_SETTINGS_DIR ?= .
INC = -I$(USER_SETTINGS_DIR) \
      -I../..

# Defines
DEF = -DWOLFSSL_USER_SETTINGS -DWOLFSSL_GENSEED_FORTEST
#DEF = -DUSE_LIBFUZZER
#CFLAGS = -fsanitize=fuzzer,address

# LD: generate map
LDFLAGS += -Wl,-Map=$(BUILD_DIR)/$(BIN).map

# LD: Entry point
LDFLAGS += -Wl,-ereset_handler

# Math lib (for DH)
LIBS = -lm

# Optimization level and place functions / data into separate sections to allow dead code removal
CFLAGS += -Os -ffunction-sections -fdata-sections -fno-builtin
# Remove unused sections and link time optimizations
LDFLAGS += -Wl,--gc-sections -flto

# Debugging
#DBGFLAGS = -ggdb -g3
CFLAGS += $(DBGFLAGS)
LDFLAGS += $(DBGFLAGS)


# FILES
SRC_C += ../../wolfcrypt/src/aes.c
SRC_C += ../../wolfcrypt/src/hmac.c
SRC_C += ../../wolfcrypt/src/random.c
SRC_C += ../../wolfcrypt/src/sha256.c
SRC_C += ../../wolfcrypt/src/misc.c
SRC_C += ../../src/wolfio.c
SRC_C += psk-ssl.c
SRC_C += psk-tls.c
SRC_C += example-client-psk.c


FILENAMES_C = $(notdir $(SRC_C))
FILENAMES_C := $(filter-out evp.c, $(FILENAMES_C))
OBJS_C = $(addprefix $(BUILD_DIR)/, $(FILENAMES_C:.c=.o))
vpath %.c $(dir $(SRC_C))

APP = example-client-psk

all: $(BUILD_DIR)/$(APP)
	@echo ""
	$(CMD_ECHO) $(SIZE) $(BUILD_DIR)/$(APP)

$(BUILD_DIR):
	$(CMD_ECHO) mkdir -p $(BUILD_DIR)

$(BUILD_DIR)/%.o: %.c
	@echo "Compiling C file: $(notdir $<)"
	$(CMD_ECHO) $(CC) $(CFLAGS) $(DEF) $(INC) -c -o $@ $<

$(BUILD_DIR)/$(APP): $(OBJS_C)
	@echo "Linking object files:"
	$(CMD_ECHO) $(CC) $(CFLAGS) $(DEF) $(INC) -o $@ $(OBJS_C)


clean:
	rm -f $(BUILD_DIR)/*.o $(BUILD_DIR)/$(APP)

