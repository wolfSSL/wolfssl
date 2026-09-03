ARTIFACT = wolfCrypt

#Build architecture/variant string, possible values: x86, armv7le, etc...
PLATFORM ?= armv7le

#Build profile, possible values: release, debug, profile, coverage
BUILD_PROFILE ?= debug

CONFIG_NAME ?= $(PLATFORM)-$(BUILD_PROFILE)
OUTPUT_DIR = build/$(CONFIG_NAME)
TARGET = $(OUTPUT_DIR)/$(ARTIFACT)
AES_TEST_TARGET = $(OUTPUT_DIR)/test_aes_request_length
HOST_TEST_TARGET = $(OUTPUT_DIR)/test_aes_request_length_host
HOST_CC ?= cc

ifeq ($(shell uname -s),Darwin)
HOST_TEST_LDFLAGS = -Wl,-dead_strip
else
HOST_TEST_LDFLAGS = -Wl,--gc-sections
endif

#Compiler definitions

CC ?= qcc -Vgcc_nto$(PLATFORM)
CXX ?= q++ -Vgcc_nto$(PLATFORM)_cxx
LD = $(CC)

INCLUDES += -I../../../ -I../../../wolfssl/wolfcrypt/port/caam/
CCFLAGS += -O2 -Wall

# For debugging print outs build with WOLFSSL_CAAM_PRINT defined
# CCFLAGS += -DWOLFSSL_CAAM_PRINT -O2 -Wall

# Setting base address for hardware

# For IMX6UL devices
# CCFLAGS += -DWOLFSSL_CAAM_IMX6UL

# For IMX6Q devices
CCFLAGS += -DWOLFSSL_CAAM_IMX6Q

# wolfSSL header included for version number
CCFLAGS += -DWOLFSSL_CUSTOM_CONFIG

#Compiler flags for build profiles
CCFLAGS_release += -O2
CCFLAGS_debug += -g -O0 -fno-builtin
CCFLAGS_coverage += -g -O0 -ftest-coverage -fprofile-arcs -nopipe -Wc,-auxbase-strip,$@
LDFLAGS_coverage += -ftest-coverage -fprofile-arcs
CCFLAGS_profile += -g -O0 -finstrument-functions
LIBS_profile += -lprofilingS

#Generic compiler flags (which include build type flags)
CCFLAGS_all += -Wall -fmessage-length=0
CCFLAGS_all += $(CCFLAGS_$(BUILD_PROFILE))
LDFLAGS_all += $(LDFLAGS_$(BUILD_PROFILE))
LIBS_all += $(LIBS_$(BUILD_PROFILE))
DEPS = -Wp,-MMD,$(OUTPUT_DIR)/$(notdir $(@:%.o=%.d)),-MT,$(OUTPUT_DIR)/$(notdir $@)

SRCS = ../../../wolfcrypt/src/port/caam/caam_error.c \
       ../../../wolfcrypt/src/port/caam/caam_driver.c \
       ../../../wolfcrypt/src/port/caam/caam_qnx.c

#Object files list
OBJS = $(addprefix $(OUTPUT_DIR)/,$(addsuffix .o, $(basename $(SRCS))))

#Compiling rule
$(OUTPUT_DIR)/%.o: %.c
	@mkdir -p $(dir $(OUTPUT_DIR)/$(notdir $@))
	$(CC) -c $(DEPS) -o $(OUTPUT_DIR)/$(notdir $@) $(INCLUDES) $(CCFLAGS_all) $(CCFLAGS) $<

#Linking rule
$(TARGET):$(OBJS)
	$(LD) -o $(TARGET) $(LDFLAGS_all) $(LDFLAGS) $(foreach f, $(OBJS), $(OUTPUT_DIR)/$(notdir $(f))) $(LIBS_all) $(LIBS)

#Rules section for default compilation and linking
all: $(TARGET)

.PHONY: test host-test
test: $(AES_TEST_TARGET) host-test

host-test: $(HOST_TEST_TARGET)
	$(HOST_TEST_TARGET)

$(AES_TEST_TARGET): test_aes_request_length.c \
        ../../../wolfcrypt/src/port/caam/caam_qnx.c \
        ../../../wolfssl/wolfcrypt/port/caam/caam_driver.h
	@mkdir -p $(dir $@)
	$(CC) -ffunction-sections -fdata-sections -o $@ $(INCLUDES) \
		$(CCFLAGS_all) $(CCFLAGS) $< $(LDFLAGS_all) $(LDFLAGS) \
		-Wl,--gc-sections $(LIBS_all) $(LIBS)

$(HOST_TEST_TARGET): test_aes_request_length.c \
        ../../../wolfcrypt/src/port/caam/caam_qnx.c \
        ../../../wolfssl/wolfcrypt/port/caam/caam_driver.h \
        test_support/qnx_test_stubs.h
	@mkdir -p $(dir $@)
	$(HOST_CC) -D__QNXNTO__ -DCAAM_QNX_TEST_HOST \
		-ffunction-sections -fdata-sections -o $@ -Itest_support \
		$(INCLUDES) $(CCFLAGS_all) $(CCFLAGS) $< \
		$(HOST_TEST_LDFLAGS) -pthread

clean:
	rm -fr $(OUTPUT_DIR)

rebuild: clean all

#Inclusion of dependencies (object files to source and includes)
-include $(OBJS:%.o=%.d)
