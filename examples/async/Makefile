CC ?= gcc
AR ?= ar
RM ?= rm -f

WOLFSSL_TOP ?= $(abspath ../..)
OBJDIR ?= build

CFLAGS ?= -O0 -g
CFLAGS += -I.
CFLAGS += -I$(WOLFSSL_TOP)
CFLAGS += -I$(WOLFSSL_TOP)/wolfssl
CFLAGS += -I$(WOLFSSL_TOP)/wolfssl/wolfcrypt
CFLAGS += -Wall -Wextra -Wpedantic -Werror
CFLAGS += -DWOLFSSL_USER_SETTINGS
CFLAGS += -DHAVE_SYS_TIME_H
CFLAGS += -DUSE_CERT_BUFFERS_256
CFLAGS += $(EXTRA_CFLAGS)

LDFLAGS ?=
LDLIBS ?=

TARGETS = async_client async_server

WOLFSSL_SRC := $(wildcard $(WOLFSSL_TOP)/src/*.c)
WOLFCRYPT_SRC := $(wildcard $(WOLFSSL_TOP)/wolfcrypt/src/*.c)
LOCAL_SRC := async_client.c async_server.c async_tls.c

WOLFSSL_OBJS := $(patsubst $(WOLFSSL_TOP)/%, $(OBJDIR)/%, $(WOLFSSL_SRC:.c=.o))
WOLFCRYPT_OBJS := $(patsubst $(WOLFSSL_TOP)/%, $(OBJDIR)/%, $(WOLFCRYPT_SRC:.c=.o))
LOCAL_OBJS := $(patsubst %.c, $(OBJDIR)/%.o, $(LOCAL_SRC))

ASYNC_CLIENT_OBJS := $(OBJDIR)/async_client.o $(OBJDIR)/async_tls.o
ASYNC_SERVER_OBJS := $(OBJDIR)/async_server.o $(OBJDIR)/async_tls.o

all: $(TARGETS)

async_client: $(ASYNC_CLIENT_OBJS) $(WOLFSSL_OBJS) $(WOLFCRYPT_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

async_server: $(ASYNC_SERVER_OBJS) $(WOLFSSL_OBJS) $(WOLFCRYPT_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

$(OBJDIR)/%.o: %.c user_settings.h
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/%.o: $(WOLFSSL_TOP)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

# Possibly empty files (avoids "warning: ISO C forbids an empty translation unit")
$(OBJDIR)/wolfcrypt/src/ecc_fp.o: CFLAGS += -Wno-pedantic
$(OBJDIR)/wolfcrypt/src/fips.o: CFLAGS += -Wno-pedantic
$(OBJDIR)/wolfcrypt/src/fips_test.o: CFLAGS += -Wno-pedantic
$(OBJDIR)/wolfcrypt/src/fipsv2.o: CFLAGS += -Wno-pedantic
$(OBJDIR)/wolfcrypt/src/selftest.o: CFLAGS += -Wno-pedantic
$(OBJDIR)/wolfcrypt/src/wolfcrypt_first.o: CFLAGS += -Wno-pedantic
$(OBJDIR)/wolfcrypt/src/wolfcrypt_last.o: CFLAGS += -Wno-pedantic

clean:
	$(RM) -r $(OBJDIR) $(TARGETS)
