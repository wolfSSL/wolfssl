ARTIFACT = wolfCrypt

#Build architecture/variant string, possible values: x86, armv7le, etc...
PLATFORM = armv7le
OUTPUT_DIR = build
TARGET = $(ARTIFACT)

CC ?= qcc -Vgcc_nto$(PLATFORM)
CXX = qcc -lang-c++ -Vgcc_nto$(PLATFORM)
LD = $(CC)

INCLUDES += -I../../../ -I../../../wolfssl/wolfcrypt/port/caam/
CCFLAGS += -O2 -Wall

# For debugging print outs build with WOLFSSL_CAAM_PRINT defined
#CCFLAGS += -DWOLFSSL_CAAM_PRINT -O2 -Wall

SRCS = \
    ../../../wolfcrypt/src/port/caam/caam_driver.c \
    ../../../wolfcrypt/src/port/caam/caam_error.c \
    ../../../wolfcrypt/src/port/caam/caam_qnx.c \

OBJS = $(addprefix $(OUTPUT_DIR)/,$(addsuffix .o, $(basename $(SRCS))))

$(OUTPUT_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) -c -o $@ $(INCLUDES) $(CCFLAGS) $<

$(TARGET):$(OBJS)
	$(LD) -o $(TARGET) $(LDFLAGS) $(OBJS) $(LIBS)

all: $(TARGET)

clean:
	rm -rf $(OUTPUT_DIR) $(ARTIFACT)

rebuild: clean all
