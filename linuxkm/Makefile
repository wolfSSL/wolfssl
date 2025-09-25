# libwolfssl Linux kernel module Makefile (wraps Kbuild-native makefile)
#
# Copyright (C) 2006-2025 wolfSSL Inc.
#
# This file is part of wolfSSL.
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 3 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA

.ONESHELL:
SHELL=bash

all: libwolfssl.ko libwolfssl.ko.signed

ifndef MODULE_TOP
    MODULE_TOP=$(CURDIR)
endif

ifndef SRC_TOP
    SRC_TOP=$(shell dirname $(MODULE_TOP))
endif

WOLFSSL_CFLAGS=-DHAVE_CONFIG_H -I$(SRC_TOP) -DBUILDING_WOLFSSL $(AM_CPPFLAGS) $(CPPFLAGS) $(AM_CFLAGS) $(CFLAGS) -Wno-declaration-after-statement -Wno-redundant-decls -DLIBWOLFSSL_GLOBAL_EXTRA_CFLAGS="\" $(KERNEL_EXTRA_CFLAGS)\""
ifdef KERNEL_EXTRA_CFLAGS
    WOLFSSL_CFLAGS += $(KERNEL_EXTRA_CFLAGS)
endif

WOLFSSL_ASFLAGS=-DHAVE_CONFIG_H -I$(SRC_TOP) -DBUILDING_WOLFSSL $(AM_CCASFLAGS) $(CCASFLAGS)

WOLFSSL_OBJ_FILES=$(patsubst %.lo, %.o, $(patsubst src/src_libwolfssl_la-%, src/%, $(patsubst src/libwolfssl_la-%, src/%, $(patsubst wolfcrypt/src/src_libwolfssl_la-%, wolfcrypt/src/%, $(src_libwolfssl_la_OBJECTS)))))

ifeq "$(ENABLED_CRYPT_TESTS)" "yes"
    WOLFSSL_OBJ_FILES+=wolfcrypt/test/test.o
else ifneq "$(ENABLED_LINUXKM_LKCAPI_REGISTER)" "none"
    WOLFSSL_OBJ_FILES+=wolfcrypt/test/test.o
else
    WOLFSSL_CFLAGS+=-DNO_CRYPT_TEST
endif

ifeq "$(ENABLED_LINUXKM_BENCHMARKS)" "yes"
    WOLFSSL_OBJ_FILES+=wolfcrypt/benchmark/benchmark.o
endif

ifeq "$(ENABLED_LINUXKM_PIE)" "yes"
    WOLFCRYPT_PIE_FILES := $(filter wolfcrypt/src/%,$(WOLFSSL_OBJ_FILES)) linuxkm/pie_redirect_table.o
    WOLFSSL_OBJ_FILES := $(WOLFCRYPT_PIE_FILES) $(filter-out $(WOLFCRYPT_PIE_FILES),$(WOLFSSL_OBJ_FILES))
endif

export WOLFSSL_CFLAGS WOLFSSL_ASFLAGS WOLFSSL_OBJ_FILES WOLFCRYPT_PIE_FILES

ifneq "$(host_triplet)" "$(build_triplet)"
    CROSS_COMPILE := 'CROSS_COMPILE=$(host_triplet)-'
endif

OVERRIDE_PATHS :=

ifdef CC
    ifneq "$(CC)" "cc"
        OVERRIDE_PATHS := $(OVERRIDE_PATHS) 'CC=$(CC)'
    endif
endif
ifdef AS
    ifneq "$(AS)" "as"
        OVERRIDE_PATHS := $(OVERRIDE_PATHS) 'AS=$(AS)'
    endif
endif
ifdef LD
    ifneq "$(LD)" "ld"
        OVERRIDE_PATHS := $(OVERRIDE_PATHS) 'LD=$(LD)'
    endif
endif

ifndef READELF
    READELF := readelf
endif

ifndef AWK
    AWK := awk
endif

ifndef TMPDIR
    TMPDIR := /tmp
endif

ifndef MAKE_TMPDIR
    MAKE_TMPDIR := $(TMPDIR)
endif

GENERATE_RELOC_TAB := $(READELF) --wide -r libwolfssl.ko |				\
	$(AWK) 'BEGIN {									\
	    n=0;									\
	    bad_relocs=0;								\
	    printf("%s\n    ",								\
	        "const unsigned int wc_linuxkm_pie_reloc_tab[] = { ");			\
	}										\
	/^Relocation section '\''\.rela\.text\.wolfcrypt'\''/ {				\
	    p=1;									\
	    next;									\
	}										\
	/^Relocation section/ {								\
	    p=0;									\
	}										\
	/^0/ {										\
	    if (p) {									\
	        if ($$3 !~ "^(R_X86_64_PLT32|R_X86_64_PC32|R_AARCH64_.*)$$") {		\
	            print "Unexpected relocation type:\n" $$0 >"/dev/stderr";		\
	            ++bad_relocs;							\
	        }									\
	        printf("0x%s%s",							\
	            gensub("^0*","",1,$$1),						\
	            ((++n%8) ? ", " : ",\n    "));					\
	    }										\
	}										\
	END {										\
	    if (bad_relocs) {								\
	        print "Found " bad_relocs " unexpected relocations." >"/dev/stderr";	\
	        exit(1);								\
	    }										\
	    print "~0U };\nconst size_t wc_linuxkm_pie_reloc_tab_length = sizeof wc_linuxkm_pie_reloc_tab / sizeof wc_linuxkm_pie_reloc_tab[0];";\
	}'

.PHONY: libwolfssl.ko
libwolfssl.ko:
	@if test -z '$(KERNEL_ROOT)'; then echo '$$KERNEL_ROOT is unset' >&2; exit 1; fi
	@if test -z '$(AM_CFLAGS)$(CFLAGS)'; then echo '$$AM_CFLAGS and $$CFLAGS are both unset.' >&2; exit 1; fi
	@if test -z '$(src_libwolfssl_la_OBJECTS)'; then echo '$$src_libwolfssl_la_OBJECTS is unset.' >&2; exit 1; fi
        # after commit 9a0ebe5011 (6.10), sources must be in $(obj).  work around this by making links to all needed sources:
	@mkdir -p '$(MODULE_TOP)/linuxkm'
	@test '$(MODULE_TOP)/module_hooks.c' -ef '$(MODULE_TOP)/linuxkm/module_hooks.c' || cp --verbose --no-dereference --symbolic-link --no-clobber '$(MODULE_TOP)'/*.[ch] '$(MODULE_TOP)/linuxkm/'
	@test '$(SRC_TOP)/wolfcrypt/src/wc_port.c' -ef '$(MODULE_TOP)/wolfcrypt/src/wc_port.c' || cp --verbose --no-dereference --symbolic-link --no-clobber --recursive '$(SRC_TOP)/wolfcrypt' '$(MODULE_TOP)/'
	@test '$(SRC_TOP)/src/wolfio.c' -ef '$(MODULE_TOP)/src/wolfio.c' || cp --verbose --no-dereference --symbolic-link --no-clobber --recursive '$(SRC_TOP)/src' '$(MODULE_TOP)/'
ifeq "$(ENABLED_LINUXKM_PIE)" "yes"
	@$(eval RELOC_TMP := $(shell mktemp "$(MAKE_TMPDIR)/wc_linuxkm_pie_reloc_tab.c.XXXXXX"))
	@[[ -f wc_linuxkm_pie_reloc_tab.c ]] || echo -e "const unsigned int wc_linuxkm_pie_reloc_tab[] = { ~0U };\nconst size_t wc_linuxkm_pie_reloc_tab_length = 1;" > wc_linuxkm_pie_reloc_tab.c
	@if [[ -f libwolfssl.ko ]]; then touch -r libwolfssl.ko "$(RELOC_TMP)"; fi
	+$(MAKE) ARCH='$(KERNEL_ARCH)' $(OVERRIDE_PATHS) $(CROSS_COMPILE) -C '$(KERNEL_ROOT)' M='$(MODULE_TOP)' $(KBUILD_EXTRA_FLAGS) CC_FLAGS_FTRACE=
	# if the above make didn't build a fresh libwolfssl.ko, then the module is already up to date and we leave it untouched, assuring stability for purposes of module-update-fips-hash.
	@if [[ ! libwolfssl.ko -nt "$(RELOC_TMP)" ]]; then rm "$(RELOC_TMP)"; exit 0; fi
	@$(GENERATE_RELOC_TAB) >| wc_linuxkm_pie_reloc_tab.c
	+$(MAKE) ARCH='$(KERNEL_ARCH)' $(OVERRIDE_PATHS) $(CROSS_COMPILE) -C '$(KERNEL_ROOT)' M='$(MODULE_TOP)' $(KBUILD_EXTRA_FLAGS) CC_FLAGS_FTRACE=
	@$(GENERATE_RELOC_TAB) >| $(RELOC_TMP)
	@if diff wc_linuxkm_pie_reloc_tab.c $(RELOC_TMP); then echo " Relocation table is stable."; else echo "PIE failed: relocation table is unstable." 1>&2; rm $(RELOC_TMP); exit 1; fi
	@rm $(RELOC_TMP)
else
	+$(MAKE) ARCH='$(KERNEL_ARCH)' $(OVERRIDE_PATHS) $(CROSS_COMPILE) -C '$(KERNEL_ROOT)' M='$(MODULE_TOP)' $(KBUILD_EXTRA_FLAGS)
endif

.PHONY: module-update-fips-hash
module-update-fips-hash: libwolfssl.ko
	@if test -z '$(FIPS_HASH)'; then echo '  $$FIPS_HASH is unset' >&2; exit 1; fi
	@if [[ ! '$(FIPS_HASH)' =~ [0-9a-fA-F]{64} ]]; then echo '  $$FIPS_HASH is malformed' >&2; exit 1; fi
	@readarray -t rodata_segment < <($(READELF) --wide --sections libwolfssl.ko | \
	    sed -E -n 's/^[[:space:]]*\[[[:space:]]*([0-9]+)\][[:space:]]+\.rodata\.wolfcrypt[[:space:]]+PROGBITS[[:space:]]+[0-9a-fA-F]+[[:space:]]+([0-9a-fA-F]+)[[:space:]].*$$/\1\n\2/p'); \
	if [[ $${#rodata_segment[@]} != 2 ]]; then echo '  unexpected rodata_segment.' >&2; exit 1; fi; \
	readarray -t verifyCore_attrs < <($(READELF) --wide --symbols libwolfssl.ko | \
	    sed -E -n 's/^[[:space:]]*[0-9]+: ([0-9a-fA-F]+)[[:space:]]+([0-9]+)[[:space:]]+OBJECT[[:space:]]+[A-Z]+[[:space:]]+[A-Z]+[[:space:]]+'"$${rodata_segment[0]}"'[[:space:]]+verifyCore$$/\1\n\2/p'); \
	if [[ $${#verifyCore_attrs[@]} != 2 ]]; then echo '  unexpected verifyCore_attrs.' >&2; exit 1; fi; \
	if [[ "$${verifyCore_attrs[1]}" != "65" ]]; then echo "  verifyCore has unexpected length $${verifyCore_attrs[1]}." >&2; exit 1; fi; \
	verifyCore_offset=$$((0x$${rodata_segment[1]} + 0x$${verifyCore_attrs[0]})); \
	current_verifyCore=$$(dd bs=1 if=libwolfssl.ko skip=$$verifyCore_offset count=64 status=none); \
	if [[ ! "$$current_verifyCore" =~ [0-9a-fA-F]{64} ]]; then echo "  verifyCore at offset $$verifyCore_offset has unexpected value." >&2; exit 1; fi; \
	if [[ '$(FIPS_HASH)' == "$$current_verifyCore" ]]; then echo '  Supplied FIPS_HASH matches existing verifyCore -- no update needed.'; exit 0; fi; \
	echo -n '$(FIPS_HASH)' | dd bs=1 conv=notrunc of=libwolfssl.ko seek=$$verifyCore_offset count=64 status=none && \
	echo "  FIPS verifyCore updated successfully." && \
	if [[ -f libwolfssl.ko.signed ]]; then $(MAKE) -C . libwolfssl.ko.signed; fi

libwolfssl.ko.signed: libwolfssl.ko
ifdef FORCE_NO_MODULE_SIG
	@echo 'Skipping module signature operation because FORCE_NO_MODULE_SIG.'
else
	@cd '$(KERNEL_ROOT)' || exit $$?;						\
	while read configline; do							\
		case "$$configline" in							\
		CONFIG_MODULE_SIG*=*)							\
			declare "$${configline%=*}"="$${configline#*=}"			\
			;;								\
		esac;									\
	done < .config || exit $$?;							\
	if [[ "$${CONFIG_MODULE_SIG}" = "y" && -n "$${CONFIG_MODULE_SIG_KEY}" && 	\
		-n "$${CONFIG_MODULE_SIG_HASH}" && ( ! -f '$(MODULE_TOP)/$@' ||		\
			'$(MODULE_TOP)/$<' -nt '$(MODULE_TOP)/$@' ) ]]; then		\
		CONFIG_MODULE_SIG_KEY="$${CONFIG_MODULE_SIG_KEY#\"}";			\
		CONFIG_MODULE_SIG_KEY="$${CONFIG_MODULE_SIG_KEY%\"}";			\
		CONFIG_MODULE_SIG_HASH="$${CONFIG_MODULE_SIG_HASH#\"}";			\
		CONFIG_MODULE_SIG_HASH="$${CONFIG_MODULE_SIG_HASH%\"}";			\
		cp -p '$(MODULE_TOP)/$<' '$(MODULE_TOP)/$@' || exit $$?;		\
		./scripts/sign-file "$${CONFIG_MODULE_SIG_HASH}"			\
				    "$${CONFIG_MODULE_SIG_KEY}"				\
				    "$${CONFIG_MODULE_SIG_KEY/%.pem/.x509}"		\
				    '$(MODULE_TOP)/$@';					\
		sign_file_exitval=$$?;							\
		if [[ $$sign_file_exitval != 0 ]]; then					\
			$(RM) -f '$(MODULE_TOP)/$@';					\
			exit $$sign_file_exitval;					\
		fi;									\
		if [[ "$(quiet)" != "silent_" ]]; then					\
			echo "  Module $@ signed by $${CONFIG_MODULE_SIG_KEY}.";	\
		fi									\
	fi
endif


.PHONY: install modules_install
install modules_install:
	+$(MAKE) -C $(KERNEL_ROOT) M=$(MODULE_TOP) src=$(SRC_TOP) INSTALL_MOD_DIR=wolfssl modules_install

.PHONY: clean
# note, must supply $(MODULE_TOP) as the src value for clean so that Kbuild is included, else
# the top Makefile (which is not for the kernel build) would be included here.
clean:
	$(RM) -rf '$(MODULE_TOP)/linuxkm'
	$(RM) -rf '$(MODULE_TOP)/wolfcrypt'
	$(RM) -rf '$(MODULE_TOP)/src'
	+$(MAKE) -C $(KERNEL_ROOT) M=$(MODULE_TOP) src=$(MODULE_TOP) clean

.PHONY: check
check:

.PHONY: distclean
distclean: clean

.PHONY: dist
dist:

.PHONY: distdir
distdir:
