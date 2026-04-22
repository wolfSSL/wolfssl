# tests/swdev/Makefile -- builds swdev.o.
#
# Standalone:  cd tests/swdev && make
# Invoked from wolfcrypt/test/include.am in the main build.

SRCDIR    ?= $(CURDIR)
WOLFROOT  ?= $(abspath $(SRCDIR)/../..)
BUILDDIR  ?= $(SRCDIR)/build

CC        ?= cc
CCAS      ?= $(CC)
LD        ?= ld
OBJCOPY   ?= objcopy
NM        ?= nm

SWDEV_LOCAL_SRCS = swdev.c

# PARENT_SRCS / PARENT_ASM_SRCS mirror the exact source set that the
# parent build compiled into libwolfssl (passed down by wolfcrypt/test/include.am).
# The configure.ac gate already requires in-tree builds, so PARENT_SRCS
# is always populated when swdev is built in-tree; fail loudly otherwise.
ifeq ($(strip $(PARENT_SRCS)),)
$(error PARENT_SRCS is empty -- swdev must be built from the top-level \
    Makefile so its source set matches the main library)
endif

SWDEV_CRYPT_SRCS = $(filter wolfcrypt/src/%,$(PARENT_SRCS))
SWDEV_SSL_SRCS   = $(filter src/%,$(PARENT_SRCS))
SWDEV_ASM_SRCS   = $(PARENT_ASM_SRCS)

# -I$(SRCDIR) routes settings.h to the swdev's user_settings.h.
# No BUILDING_WOLFSSL so WOLFSSL_API/LOCAL stay empty; then -fvisibility=hidden
# hides every emitted symbol.
CPPFLAGS_SWDEV = \
    $(PARENT_CPPFLAGS) \
    -DWOLFSSL_USER_SETTINGS \
    -I$(SRCDIR) \
    -I$(WOLFROOT) \
    -I$(WOLFROOT)/wolfssl

# -fvisibility=hidden + -fno-common mark every symbol hidden at the ELF
# level (ABI-safe: attribute only, no struct layout impact). Optimization
# level and other flags are inherited from the parent build (PARENT_*_CFLAGS)
# so codegen stays in lockstep with libwolfssl. Use EXTRA_SWDEV_CFLAGS to
# append debug flags (e.g. -O0 -ggdb) on demand.
CFLAGS_SWDEV = \
    $(PARENT_BUILD_CFLAGS) \
    $(PARENT_CFLAGS) \
    -fvisibility=hidden \
    -fno-common \
    -Wno-pragmas \
    $(EXTRA_SWDEV_CFLAGS)

CCASFLAGS_SWDEV = \
    $(PARENT_BUILD_CCASFLAGS) \
    $(PARENT_CCASFLAGS)

CRYPT_OBJS  = $(patsubst wolfcrypt/src/%.c,$(BUILDDIR)/wc/%.o,$(SWDEV_CRYPT_SRCS))
SSL_OBJS    = $(patsubst src/%.c,$(BUILDDIR)/ssl/%.o,$(SWDEV_SSL_SRCS))
ASM_OBJS    = $(patsubst wolfcrypt/src/%.S,$(BUILDDIR)/wc/%.o,$(SWDEV_ASM_SRCS))
LOCAL_OBJS  = $(patsubst %.c,$(BUILDDIR)/local/%.o,$(SWDEV_LOCAL_SRCS))
ALL_OBJS    = $(CRYPT_OBJS) $(SSL_OBJS) $(ASM_OBJS) $(LOCAL_OBJS)

.PHONY: all clean
all: $(BUILDDIR)/swdev.o

$(BUILDDIR)/wc/%.o: $(WOLFROOT)/wolfcrypt/src/%.c $(SRCDIR)/user_settings.h $(WOLFROOT)/wolfssl/options.h | $(BUILDDIR)/wc
	$(CC) $(CPPFLAGS_SWDEV) $(CFLAGS_SWDEV) -c $< -o $@

$(BUILDDIR)/wc/%.o: $(WOLFROOT)/wolfcrypt/src/%.S $(SRCDIR)/user_settings.h $(WOLFROOT)/wolfssl/options.h | $(BUILDDIR)/wc
	$(CCAS) $(CPPFLAGS_SWDEV) $(CCASFLAGS_SWDEV) -c $< -o $@

$(BUILDDIR)/ssl/%.o: $(WOLFROOT)/src/%.c $(SRCDIR)/user_settings.h $(WOLFROOT)/wolfssl/options.h | $(BUILDDIR)/ssl
	$(CC) $(CPPFLAGS_SWDEV) $(CFLAGS_SWDEV) -c $< -o $@

$(BUILDDIR)/local/%.o: $(SRCDIR)/%.c $(SRCDIR)/swdev.h $(SRCDIR)/user_settings.h $(WOLFROOT)/wolfssl/options.h | $(BUILDDIR)/local
	$(CC) $(CPPFLAGS_SWDEV) $(CFLAGS_SWDEV) -c $< -o $@

$(BUILDDIR)/swdev.partial.o: $(ALL_OBJS)
	$(LD) -r -o $@ $(ALL_OBJS)

$(BUILDDIR)/swdev.o: $(BUILDDIR)/swdev.partial.o
	@# --keep-global-symbol localizes every global symbol *except* the
	@# named one. We can't rely on --localize-hidden here because
	@# wolfssl/wolfcrypt/libwolfssl_sources.h auto-defines BUILDING_WOLFSSL
	@# at the top of every compiled source, which expands WOLFSSL_API to
	@# visibility("default") and overrides the command-line
	@# -fvisibility=hidden. --keep-global-symbol sidesteps that by matching
	@# on symbol name directly.
	$(OBJCOPY) --keep-global-symbol=wc_SwDev_Callback $< $@
	@# Sanity-check: only wc_SwDev_Callback may be externally visible.
	@visible=$$( $(NM) --extern-only --defined-only $@ | awk '{print $$3}' \
	             | grep -v '^wc_SwDev_Callback$$' || true); \
	if [ -n "$$visible" ]; then \
	    echo "error: unexpected externally-visible symbols in $@:"; \
	    echo "$$visible"; \
	    exit 1; \
	fi

$(BUILDDIR) $(BUILDDIR)/wc $(BUILDDIR)/ssl $(BUILDDIR)/local:
	mkdir -p $@

clean:
	rm -rf $(BUILDDIR)
