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
ifeq "$(FIPS_OPTEST)" "1"
    WOLFSSL_CFLAGS += -DFIPS_OPTEST
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

ifeq "$(ENABLED_KERNEL_BENCHMARKS)" "yes"
    WOLFSSL_OBJ_FILES+=wolfcrypt/benchmark/benchmark.o
endif

ifeq "$(ENABLED_LINUXKM_PIE)" "yes"
    WOLFCRYPT_PIE_FILES := \
	$(filter wolfcrypt/src/%,$(WOLFSSL_OBJ_FILES)) \
	linuxkm/pie_redirect_table.o \
	linuxkm/wc_linuxkm_pie_reloc_tab.o
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

GENERATE_SECTION_MAP := $(AWK) 'BEGIN { printf("") >ENVIRON["SECTION_MAP"]; }		\
	{										\
	    if ($$7 !~ "^[0-9]+$$")							\
		next;									\
	    if ($$4 == "SECTION") {							\
		sections[$$7] = $$8;							\
		next;									\
	    }										\
	    if (($$4 == "NOTYPE") || ($$4 == "OBJECT") || ($$4 == "FUNC")) {		\
		if (($$8 == "$$d") || ($$8 == "$$t"))					\
		    next;								\
		if ($$7 in sections) {							\
		    if (sections[$$7] ~ "_wolfcrypt$$")					\
			print $$8 "\t" sections[$$7] >>ENVIRON["SECTION_MAP"];		\
		} else									\
		    print $$8 " is in section " $$7 " with no name mapping." >"/dev/stderr";\
	    }										\
	}'

GENERATE_RELOC_TAB := $(AWK) '								\
        BEGIN {                                                         		\
	    n=0;									\
	    bad_relocs=0;								\
	    print "\#include <wolfssl/wolfcrypt/libwolfssl_sources.h>";			\
	    printf("%s\n    ",								\
		"WOLFSSL_LOCAL const unsigned int wc_linuxkm_pie_reloc_tab[] = { ");	\
	    if ("SECTION_MAP" in ENVIRON) {						\
		while (getline <ENVIRON["SECTION_MAP"] > 0)				\
		    section_map[$$1] = $$2;						\
		close(ENVIRON["SECTION_MAP"]);						\
	    }										\
	}										\
	/^Relocation section '\''\.rela?\.text_wolfcrypt'\''/ {				\
	    p=1;									\
	    next;									\
	}										\
	/^Relocation section/ {								\
	    p=0;									\
	}										\
	/^0/ {										\
	    if (p) {									\
		if ($$3 !~ "^(R_X86_64_PLT32|R_X86_64_PC32|R_AARCH64_.*|R_ARM.*)$$") {	\
		    print "Unexpected relocation type:\n" $$0 >"/dev/stderr";		\
		    ++bad_relocs;							\
		}									\
		if ($$5 in section_map)							\
		    section = section_map[$$5];						\
		else if ($$5 ~ "^\\.")							\
		    section = $$5;							\
		else									\
		    section = "";							\
		if (section) {								\
		    switch (section) {							\
		    case ".text_wolfcrypt":						\
			section_tag = 0;						\
			break;								\
		    case ".rodata_wolfcrypt":						\
			section_tag = 1;						\
			break;								\
		    case ".data_wolfcrypt":						\
			section_tag = 2;						\
			break;								\
		    case ".bss_wolfcrypt":						\
			section_tag = 3;						\
			break;								\
		    default:								\
			print "Unexpected section:\n" $$0 >"/dev/stderr";		\
			++bad_relocs;							\
			section_tag = 4;						\
		    }									\
		} else {								\
		    print "Unresolvable symbol reference for relocation:\n" $$0 >"/dev/stderr";\
		    ++bad_relocs;							\
		    section_tag = 4;							\
		}									\
		if (strtonum("0x" gensub("^0*","",1,$$1)) >= lshift(1, 29)) {		\
		    print "Relocation offset overflow:" >"/dev/stderr";			\
		    print >"/dev/stderr";						\
		    exit(1);								\
		}									\
		printf("0x%xU%s",							\
		       or(strtonum("0x" gensub("^0*","",1,$$1)),			\
			  lshift(section_tag, 29)),					\
		       ((++n%8) ? ", " : ",\n	 "));					\
	    }										\
	}										\
	END {										\
	    if (bad_relocs) {								\
		print "Found " bad_relocs " unresolvable relocations." >"/dev/stderr";	\
		exit(1);								\
	    }										\
	    print "~0U };\nWOLFSSL_LOCAL const unsigned long wc_linuxkm_pie_reloc_tab_length = sizeof wc_linuxkm_pie_reloc_tab / sizeof wc_linuxkm_pie_reloc_tab[0];";\
	}'

ifeq "$(V)" "1"
    vflag := --verbose
endif

# This rule is .PHONY because it doesn't actually build the module -- Kbuild
# does, and we always need to call Kbuild to enforce rebuild for dependencies
# and config changes.
.PHONY: libwolfssl.ko
libwolfssl.ko:
	@set -e
	@[[ '$(V)' == 1 ]] && { echo 'MODULE_TOP = "$(MODULE_TOP)"';
	echo 'SRC_TOP = "$(SRC_TOP)"';
	echo 'AM_CPPFLAGS = "$(AM_CPPFLAGS)"';
	echo 'CPPFLAGS = "$(CPPFLAGS)"';
	echo 'AM_CFLAGS = "$(AM_CFLAGS)"';
	echo 'CFLAGS = "$(CFLAGS)"';
	echo 'KERNEL_EXTRA_CFLAGS = "$(KERNEL_EXTRA_CFLAGS)"';
	echo 'FIPS_OPTEST = "$(FIPS_OPTEST)"';
	echo 'AM_CCASFLAGS = "$(AM_CCASFLAGS)"';
	echo 'CCASFLAGS = "$(CCASFLAGS)"';
	echo 'src_libwolfssl_la_OBJECTS = "$(src_libwolfssl_la_OBJECTS)"';
	echo 'ENABLED_CRYPT_TESTS = "$(ENABLED_CRYPT_TESTS)"';
	echo 'ENABLED_LINUXKM_LKCAPI_REGISTER = "$(ENABLED_LINUXKM_LKCAPI_REGISTER)"';
	echo 'ENABLED_LINUXKM_BENCHMARKS = "$(ENABLED_LINUXKM_BENCHMARKS)"';
	echo 'ENABLED_LINUXKM_PIE = "$(ENABLED_LINUXKM_PIE)"';
	echo 'host_triplet = "$(host_triplet)"';
	echo 'build_triplet = "$(build_triplet)"';
	echo 'CC = "$(CC)"';
	echo 'AS = "$(AS)"';
	echo 'LD = "$(LD)"';
	echo 'READELF = "$(READELF)"';
	echo 'AWK = "$(AWK)"';
	echo 'TMPDIR = "$(TMPDIR)"';
	echo 'MAKE_TMPDIR = "$(MAKE_TMPDIR)"';
	echo 'KERNEL_ROOT = "$(KERNEL_ROOT)"';
	echo 'obj = "$(obj)"';
	echo 'RM = "$(RM)"';
	echo 'KERNEL_ARCH = "$(KERNEL_ARCH)"';
	echo 'FIPS_HASH = "$(FIPS_HASH)"';
	echo 'MAKE = "$(MAKE)"';
	echo 'ENABLED_ASM = "$(ENABLED_ASM)"';
	echo 'CFLAGS_FPU_DISABLE = "$(CFLAGS_FPU_DISABLE)"';
	echo 'CFLAGS_FPU_ENABLE = "$(CFLAGS_FPU_ENABLE)"';
	echo 'CFLAGS_SIMD_DISABLE = "$(CFLAGS_SIMD_DISABLE)"';
	echo 'CFLAGS_SIMD_ENABLE = "$(CFLAGS_SIMD_ENABLE)"';
	echo 'CFLAGS_AUTO_VECTORIZE_DISABLE = "$(CFLAGS_AUTO_VECTORIZE_DISABLE)"';
	echo 'CFLAGS_AUTO_VECTORIZE_ENABLE = "$(CFLAGS_AUTO_VECTORIZE_ENABLE)"';
	echo 'ASFLAGS_FPU_DISABLE_SIMD_ENABLE = "$(ASFLAGS_FPU_DISABLE_SIMD_ENABLE)"';
	echo 'ASFLAGS_FPU_ENABLE_SIMD_DISABLE = "$(ASFLAGS_FPU_ENABLE_SIMD_DISABLE)"';
	echo 'ASFLAGS_FPUSIMD_DISABLE = "$(ASFLAGS_FPUSIMD_DISABLE)"';
	echo 'ASFLAGS_FPUSIMD_ENABLE = "$(ASFLAGS_FPUSIMD_ENABLE)"'; }
	@function resolved_link_is_equal() { [[ -L "$$1" && "$$(readlink -f "$$1")" == "$$(readlink -f "$$2")" ]]; }
	@if test -z '$(KERNEL_ROOT)'; then echo '$$KERNEL_ROOT is unset' >&2; exit 1; fi
	@if test -z '$(AM_CFLAGS)$(CFLAGS)'; then echo '$$AM_CFLAGS and $$CFLAGS are both unset.' >&2; exit 1; fi
	@if test -z '$(src_libwolfssl_la_OBJECTS)'; then echo '$$src_libwolfssl_la_OBJECTS is unset.' >&2; exit 1; fi
	# after commit 9a0ebe5011 (6.10), sources must be in $(obj).  work around this by making links to all needed sources:
	@mkdir -p '$(MODULE_TOP)/linuxkm'
	@resolved_link_is_equal '$(MODULE_TOP)/linuxkm/module_hooks.c' '$(MODULE_TOP)/module_hooks.c' || cp $(vflag) --no-dereference --symbolic-link --no-clobber '$(MODULE_TOP)'/*.[ch] '$(MODULE_TOP)/linuxkm/'
	@resolved_link_is_equal '$(MODULE_TOP)/wolfcrypt/src/wc_port.c' '$(SRC_TOP)/wolfcrypt/src/wc_port.c' || cp $(vflag) --no-dereference --symbolic-link --no-clobber --recursive '$(SRC_TOP)/wolfcrypt' '$(MODULE_TOP)/'
	@resolved_link_is_equal '$(MODULE_TOP)/src/wolfio.c' '$(SRC_TOP)/src/wolfio.c' || cp $(vflag) --no-dereference --symbolic-link --no-clobber --recursive '$(SRC_TOP)/src' '$(MODULE_TOP)/'
ifeq "$(FIPS_OPTEST)" "1"
	@resolved_link_is_equal '$(MODULE_TOP)/linuxkm/optest-140-3/linuxkm_optest_wrapper.c' '$(SRC_TOP)/../fips/optest-140-3/linuxkm_optest_wrapper.c' || cp $(vflag) --no-dereference --symbolic-link --no-clobber --recursive '$(SRC_TOP)/../fips/optest-140-3' '$(MODULE_TOP)/linuxkm/'
endif
ifeq "$(ENABLED_LINUXKM_PIE)" "yes"
	@[[ -f '$(MODULE_TOP)/linuxkm/wc_linuxkm_pie_reloc_tab.c' && ! -L '$(MODULE_TOP)/linuxkm/wc_linuxkm_pie_reloc_tab.c' ]] || \
		{ $(RM) -f '$(MODULE_TOP)/linuxkm/wc_linuxkm_pie_reloc_tab.c' && $(GENERATE_RELOC_TAB) < /dev/null > '$(MODULE_TOP)/linuxkm/wc_linuxkm_pie_reloc_tab.c'; }
	@RELOC_TMP=$$(mktemp "$(MAKE_TMPDIR)/wc_linuxkm_pie_reloc_tab.c.XXXXXX")
	@trap 'rm "$$RELOC_TMP"' EXIT
	@if [[ -f "$@" ]]; then touch -r "$@" "$$RELOC_TMP"; fi
	+$(MAKE) ARCH='$(KERNEL_ARCH)' $(OVERRIDE_PATHS) $(CROSS_COMPILE) -C '$(KERNEL_ROOT)' M='$(MODULE_TOP)' $(KBUILD_EXTRA_FLAGS) CC_FLAGS_FTRACE=
	# if the above make didn't build a fresh libwolfssl.ko, then the module is already up to date and we leave it untouched, assuring stability for purposes of module-update-fips-hash.
	@if [[ ! "$@" -nt "$$RELOC_TMP" ]]; then echo '  Module already up-to-date.'; exit 0; fi
	@SECTION_MAP=$$(mktemp)
	@trap 'rm "$$SECTION_MAP"' EXIT
	@export SECTION_MAP
	@$(READELF) --wide --symbols "$@" | $(GENERATE_SECTION_MAP)
	@$(READELF) --wide --relocs "$@" | $(GENERATE_RELOC_TAB) >| '$(MODULE_TOP)/linuxkm/wc_linuxkm_pie_reloc_tab.c'
	+$(MAKE) ARCH='$(KERNEL_ARCH)' $(OVERRIDE_PATHS) $(CROSS_COMPILE) -C '$(KERNEL_ROOT)' M='$(MODULE_TOP)' $(KBUILD_EXTRA_FLAGS) CC_FLAGS_FTRACE=
	@$(READELF) --wide --relocs "$@" | $(GENERATE_RELOC_TAB) >| "$$RELOC_TMP"
	@if diff '$(MODULE_TOP)/linuxkm/wc_linuxkm_pie_reloc_tab.c' "$$RELOC_TMP"; then echo " Relocation table is stable."; else echo "PIE failed: relocation table is unstable." 1>&2; exit 1; fi
else
	+$(MAKE) ARCH='$(KERNEL_ARCH)' $(OVERRIDE_PATHS) $(CROSS_COMPILE) -C '$(KERNEL_ROOT)' M='$(MODULE_TOP)' $(KBUILD_EXTRA_FLAGS)
endif

.PHONY: module-update-fips-hash
module-update-fips-hash: libwolfssl.ko
	@set -e
	@if test -z '$(FIPS_HASH)'; then echo '	 $$FIPS_HASH is unset' >&2; exit 1; fi
	@if [[ ! '$(FIPS_HASH)' =~ [0-9a-fA-F]{64} ]]; then echo '  $$FIPS_HASH is malformed' >&2; exit 1; fi
	@readarray -t rodata_segment < <($(READELF) --wide --sections "$<" | \
	    sed -E -n 's/^[[:space:]]*\[[[:space:]]*([0-9]+)\][[:space:]]+\.rodata_wolfcrypt[[:space:]]+PROGBITS[[:space:]]+[0-9a-fA-F]+[[:space:]]+([0-9a-fA-F]+)[[:space:]].*$$/\1\n\2/p'); \
	if [[ $${#rodata_segment[@]} != 2 ]]; then echo '  unexpected rodata_segment.' >&2; exit 1; fi; \
	readarray -t verifyCore_attrs < <($(READELF) --wide --symbols "$<" | \
	    sed -E -n 's/^[[:space:]]*[0-9]+: ([0-9a-fA-F]+)[[:space:]]+([0-9]+)[[:space:]]+OBJECT[[:space:]]+[A-Z]+[[:space:]]+[A-Z]+[[:space:]]+'"$${rodata_segment[0]}"'[[:space:]]+verifyCore$$/\1\n\2/p'); \
	if [[ $${#verifyCore_attrs[@]} != 2 ]]; then echo '  unexpected verifyCore_attrs.' >&2; exit 1; fi; \
	if [[ "$${verifyCore_attrs[1]}" != "65" ]]; then echo "	 verifyCore has unexpected length $${verifyCore_attrs[1]}." >&2; exit 1; fi; \
	verifyCore_offset=$$((0x$${rodata_segment[1]} + 0x$${verifyCore_attrs[0]})); \
	current_verifyCore=$$(dd bs=1 if="$<" skip=$$verifyCore_offset count=64 status=none); \
	if [[ ! "$$current_verifyCore" =~ [0-9a-fA-F]{64} ]]; then echo "  verifyCore at offset $$verifyCore_offset has unexpected value." >&2; exit 1; fi; \
	if [[ '$(FIPS_HASH)' == "$$current_verifyCore" ]]; then echo '	Supplied FIPS_HASH matches existing verifyCore -- no update needed.'; exit 0; fi; \
	echo -n '$(FIPS_HASH)' | dd bs=1 conv=notrunc of="$<" seek=$$verifyCore_offset count=64 status=none && \
	echo "	FIPS verifyCore updated successfully." && \
	if [[ -f libwolfssl.ko.signed ]]; then $(MAKE) -C . libwolfssl.ko.signed; fi

libwolfssl.ko.signed: libwolfssl.ko
ifdef FORCE_NO_MODULE_SIG
	@echo 'Skipping module signature operation because FORCE_NO_MODULE_SIG.'
else
	@set -e
	@cd '$(KERNEL_ROOT)'
	while read configline; do
		case "$$configline" in
		CONFIG_MODULE_SIG*=*)
			declare "$${configline%=*}"="$${configline#*=}"
			;;
		esac
	done < .config
	if [[ "$${CONFIG_MODULE_SIG}" = "y" && -n "$${CONFIG_MODULE_SIG_KEY}" && \
		-n "$${CONFIG_MODULE_SIG_HASH}" && ( ! -f '$(MODULE_TOP)/$@' || \
			'$(MODULE_TOP)/$<' -nt '$(MODULE_TOP)/$@' ) ]]; then
		CONFIG_MODULE_SIG_KEY="$${CONFIG_MODULE_SIG_KEY#\"}"
		CONFIG_MODULE_SIG_KEY="$${CONFIG_MODULE_SIG_KEY%\"}"
		CONFIG_MODULE_SIG_HASH="$${CONFIG_MODULE_SIG_HASH#\"}"
		CONFIG_MODULE_SIG_HASH="$${CONFIG_MODULE_SIG_HASH%\"}"
		cp -p '$(MODULE_TOP)/$<' '$(MODULE_TOP)/$@' || exit $$?
		./scripts/sign-file "$${CONFIG_MODULE_SIG_HASH}" \
				    "$${CONFIG_MODULE_SIG_KEY}" \
				    "$${CONFIG_MODULE_SIG_KEY/%.pem/.x509}" \
				    '$(MODULE_TOP)/$@'
		sign_file_exitval=$$?
		if [[ $$sign_file_exitval != 0 ]]; then
			$(RM) -f '$(MODULE_TOP)/$@'
			exit $$sign_file_exitval
		fi
		if [[ "$(quiet)" != "silent_" ]]; then
			echo "	Module $@ signed by $${CONFIG_MODULE_SIG_KEY}."
		fi
	fi
endif


.PHONY: install modules_install
install modules_install:
	+$(MAKE) -C $(KERNEL_ROOT) M=$(MODULE_TOP) src=$(SRC_TOP) INSTALL_MOD_DIR=wolfssl modules_install

.PHONY: clean
# note, must supply $(MODULE_TOP) as the src value for clean so that Kbuild is included, else
# the top Makefile (which is not for the kernel build) would be included here.
clean:
	+$(MAKE) -C $(KERNEL_ROOT) M=$(MODULE_TOP) src=$(MODULE_TOP) clean
	$(RM) -rf '$(MODULE_TOP)/linuxkm'
	$(RM) -rf '$(MODULE_TOP)/wolfcrypt'
	$(RM) -rf '$(MODULE_TOP)/src'

.PHONY: check
check:

.PHONY: distclean
distclean: clean

.PHONY: dist
dist:

.PHONY: distdir
distdir:
