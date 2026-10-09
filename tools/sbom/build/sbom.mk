# sbom.mk - shared plain-Make fragment for wolfssl-compliance-tooling SBOM generation.
#
# One driver does the work; each product describes itself with a few variables
# and includes this fragment to get an `sbom` target. It is the plain-Make
# counterpart of sbom.am (autotools) and sbom.cmake (CMake). All three call the
# same driver, so the three build systems emit byte-comparable SBOMs.
#
# The including Makefile MUST set, before `include .../build/sbom.mk`:
#   SBOM_NAME        Product name recorded in the SBOM (e.g. wolfboot).
#
# Composition - set at least one:
#   SBOM_SRCS        Source files compiled into the artifact (tier E), e.g.:
#                      SBOM_SRCS := $(patsubst %.o,%.c,$(OBJS))
#   SBOM_LIB         Path to the built library to hash (tier R/L/S).
#
# Config - set one:
#   SBOM_CFLAGS      Build CFLAGS whose -D tokens describe the config.
#                    The driver keeps the -D tokens and forwards -I/-isystem;
#                    all other flags are dropped.
#   SBOM_OPTIONS_H   A pre-expanded flat #define header (verbatim, scrubbed).
#   SBOM_USER_SETTINGS  A user_settings.h.
#   SBOM_SOURCE_ONLY = 1   Source-inventory SBOM with no build-config macros.
#
# Config, strongly recommended alongside SBOM_CFLAGS:
#   SBOM_SETTINGS_H     Settings header -include'd during the capture, so the
#                       macros it derives from the -D set are recorded too.
#                       Any product whose configuration lives in a
#                       user_settings.h MUST set this. Without it the capture
#                       reads an empty translation unit and records only the
#                       literal -D list, which for a gated header (wolfBoot's
#                       user_settings.h derives HAVE_ECC from
#                       WOLFBOOT_SIGN_ECC256) silently omits the entire
#                       derived configuration.
#   SBOM_INCLUDE_DIRS   Extra -I paths for the capture, space-separated, so
#                       SBOM_SETTINGS_H can resolve the headers it pulls in.
#
# Version - set one:
#   SBOM_VERSION         Literal version string, OR
#   SBOM_VERSION_FILE +  Header to read and the macro to read from it, e.g.:
#   SBOM_VERSION_MACRO     SBOM_VERSION_FILE  = include/wolfboot/version.h
#                          SBOM_VERSION_MACRO = LIBWOLFBOOT_VERSION_STRING
#
# Optional (defaults shown):
#   SBOM_PREREQS          Targets to build before the SBOM runs. Use this for
#                         generated headers the capture needs: wolfBoot's
#                         include/target.h carries the flash layout and is
#                         #include'd by its user_settings.h, so the capture
#                         cannot preprocess without it.
#   SBOM_ROOT             Product root. Default: current directory.
#   SBOM_LICENSE_FILE     License file. Default: $(SBOM_ROOT)/LICENSE.
#   SBOM_COMPONENT_TYPE   What kind of artifact this is: CycloneDX
#                         component.type, mirrored to SPDX
#                         primaryPackagePurpose. Default: library. A
#                         bootloader or a flashed image should say firmware.
#   SBOM_LICENSE_OVERRIDE SPDX expression recorded instead of the one inferred
#                         from SBOM_LICENSE_FILE. Needed whenever that file is
#                         the *full* licence text rather than a licensing
#                         statement: the GPL text never states whether the
#                         project grants "or any later version", so inference
#                         cannot distinguish GPL-3.0-only from
#                         GPL-3.0-or-later and defaults to -only.
#   SBOM_LICENSE_TEXT     Plain-text licence embedded for a LicenseRef-* used
#                         in SBOM_LICENSE_OVERRIDE (required by SPDX 2.3).
#   SBOM_GEN              Path to gen-sbom. Default: driver auto-discovery.
#   GEN_SBOM              Legacy alias for SBOM_GEN.
#   SBOM_NO_ARTIFACT_HASH = 1   As-built FIPS/kernel: do not re-hash.
#   SBOM_DEP_WOLFSSL      yes/no - record wolfSSL as a dependency.
#   SBOM_DEP_WOLFCRYPT    yes/no - record wolfCrypt as a nested component
#                         (PURL; matching uses the wolfssl CPE).
#   SBOM_DEP_OPENSSL      yes/no - record OpenSSL as a dependency.
#   SBOM_DEP_LIBZ         yes/no - record zlib. Pass the product's real option.
#   SBOM_DOCUMENT_NAMESPACE  SPDX documentNamespace override.
#   SBOM_CRYPTO_ONLY      auto/yes/no - whether only the wolfCrypt subset of
#                         the wolfSSL release is compiled in. Default auto:
#                         read WOLFCRYPT_ONLY out of the captured macros,
#                         which needs SBOM_SETTINGS_H to be set.
#   SBOM_WOLFSSL_VERSION  Explicit wolfSSL version for --dep-version. When
#                         unset and SBOM_DEP_WOLFSSL=yes, falls back to
#                         $(WOLFSSL_DIR)/wolfssl/version.h
#                         (LIBWOLFSSL_VERSION_STRING), matching sbom.am.
#                         Also used as the wolfcrypt version when
#                         SBOM_DEP_WOLFCRYPT=yes and no wolfcrypt= override
#                         is in SBOM_DEP_VERSION.
#   SBOM_DEP_VERSION      Extra --dep-version KEY=VER tokens (space-separated).
#   HOSTCC                Host C compiler for macro capture. Default: cc.
#   CRA_PYTHON            Python interpreter. Default: python3.
#
# The driver path is derived from this fragment's own location, so a product
# that vendors share/ into tools/sbom/ needs no path configuration.
#
# Source-list staging uses $(CURDIR)/.<target>-wolfssl-compliance-tooling-srcs.txt (not mktemp).
# GNU Make expands $${TMPDIR:-/tmp} as an empty Make variable named
# "TMPDIR:-/tmp", which produced "/wolfssl-compliance-tooling-srcs.XXXXXX" and broke every
# host. The CURDIR file is .gitignore'd; avoid parallel make -j of the *same*
# SBOM target (two recipes would share one staging file). Distinct targets
# (sbom vs sbom-hal) use distinct filenames via $(1).
#
# Shell variables inside wolfssl_compliance_tooling_sbom_rule need $$$$name (not $$name):
# $(call)/$(eval) expands the define once, then the recipe expands again.
# $$name becomes $n + ame (empty single-letter Make var) after that double
# expansion; $$$$name survives as $name for the shell.
#
# That same double expansion is why SBOM_CFLAGS is referenced as
# $$($(2)CFLAGS) rather than $($(2)CFLAGS). A single $ interpolates the CFLAGS
# *value* into the rule text at eval time, and the recipe expansion then
# re-scans it. Any `$` surviving in that value is reinterpreted as a Make
# reference: wolfBoot passes -DBOOTLOADER_PARTITION_SIZE=$$(( A - B )), whose
# `$((` was read as a variable named `( A - B )`, expanded to nothing, and
# left the SBOM recording the literal value `)`. Deferring with $$( ) hands
# the arithmetic to the shell, which is what the compile recipes already do.
#
# To instantiate a second target, set another variable prefix and call:
#   $(eval $(call wolfssl_compliance_tooling_sbom_rule,sbom-hal,SBOM_HAL_))
# using SBOM_HAL_NAME, SBOM_HAL_SRCS, SBOM_HAL_CFLAGS, and so on.

SBOM_MK_DIR   := $(dir $(lastword $(MAKEFILE_LIST)))
SBOM_DRIVER   ?= $(abspath $(SBOM_MK_DIR)/../sbom-driver)

SBOM_ROOT     ?= $(CURDIR)
SBOM_LICENSE_FILE ?= $(SBOM_ROOT)/LICENSE
HOSTCC        ?= cc

define wolfssl_compliance_tooling_sbom_rule
.PHONY: $(1)
$(1): $($(2)PREREQS)
	@test -n "$($(2)NAME)" || { echo "ERROR: set $(2)NAME"; exit 1; }
	@test -n "$(strip $($(2)SRCS))$($(2)LIB)" || \
	    { echo "ERROR: set $(2)SRCS or $(2)LIB"; exit 1; }
	@set -e; \
	if [ -n "$(strip $($(2)SRCS))" ]; then \
	    trap 'rm -f "$(CURDIR)/.$(1)-wolfssl-compliance-tooling-srcs.txt"' EXIT INT TERM HUP; \
	    printf '%s\n' $($(2)SRCS) > "$(CURDIR)/.$(1)-wolfssl-compliance-tooling-srcs.txt"; \
	fi; \
	dep_ver=""; \
	if [ -n "$($(2)DEP_VERSION)" ]; then \
	    for dv in $($(2)DEP_VERSION); do \
	        dep_ver="$$$$dep_ver --dep-version $$$$dv"; \
	    done; \
	fi; \
	if [ "$($(2)DEP_WOLFSSL)" = "yes" ] || [ "$($(2)DEP_WOLFSSL)" = "1" ]; then \
	    wv="$($(2)WOLFSSL_VERSION)"; \
	    if [ -z "$$$$wv" ] && [ -n "$(WOLFSSL_DIR)" ] && \
	        [ -f "$(WOLFSSL_DIR)/wolfssl/version.h" ]; then \
	        wv=`sed -n 's/.*LIBWOLFSSL_VERSION_STRING[[:space:]]*"\([^"]*\)".*/\1/p' \
	            "$(WOLFSSL_DIR)/wolfssl/version.h" | head -1`; \
	    fi; \
	    if [ -n "$$$$wv" ]; then \
	        dep_ver="$$$$dep_ver --dep-version wolfssl=$$$$wv"; \
	    fi; \
	fi; \
	if [ "$($(2)DEP_WOLFCRYPT)" = "yes" ] || [ "$($(2)DEP_WOLFCRYPT)" = "1" ]; then \
	    case " $$$$dep_ver " in \
	        *" --dep-version wolfcrypt="*) ;; \
	        *) \
	            cv="$($(2)WOLFSSL_VERSION)"; \
	            if [ -z "$$$$cv" ] && [ -n "$(WOLFSSL_DIR)" ] && \
	                [ -f "$(WOLFSSL_DIR)/wolfssl/version.h" ]; then \
	                cv=`sed -n 's/.*LIBWOLFSSL_VERSION_STRING[[:space:]]*"\([^"]*\)".*/\1/p' \
	                    "$(WOLFSSL_DIR)/wolfssl/version.h" | head -1`; \
	            fi; \
	            if [ -n "$$$$cv" ]; then \
	                dep_ver="$$$$dep_ver --dep-version wolfcrypt=$$$$cv"; \
	            fi; \
	            ;; \
	    esac; \
	fi; \
	CRA_PYTHON="$(CRA_PYTHON)" HOSTCC="$(or $($(2)HOSTCC),$(HOSTCC))" \
	"$(or $($(2)DRIVER),$(SBOM_DRIVER))" \
	    --name "$($(2)NAME)" \
	    --root "$(or $($(2)ROOT),$(SBOM_ROOT))" \
	    --license-file "$(or $($(2)LICENSE_FILE),$(SBOM_LICENSE_FILE))" \
	    --skip-missing \
	    $(if $(strip $($(2)SRCS)),--srcs-file "$(CURDIR)/.$(1)-wolfssl-compliance-tooling-srcs.txt") \
	    $(if $($(2)LIB),--lib "$($(2)LIB)") \
	    $(if $(filter 1,$($(2)NO_ARTIFACT_HASH)),--no-artifact-hash) \
	    $(if $(filter 1,$($(2)SOURCE_ONLY)),--source-only) \
	    $(if $($(2)CFLAGS),--cflags="$$($(2)CFLAGS)") \
	    $(if $($(2)SETTINGS_H),--settings-h "$($(2)SETTINGS_H)") \
	    $(foreach d,$($(2)INCLUDE_DIRS),--include-dir "$(d)") \
	    $(if $($(2)OPTIONS_H),--options-h "$($(2)OPTIONS_H)") \
	    $(if $($(2)USER_SETTINGS),--user-settings "$($(2)USER_SETTINGS)") \
	    $(if $($(2)COMPONENT_TYPE),--component-type "$($(2)COMPONENT_TYPE)") \
	    $(if $($(2)LICENSE_OVERRIDE),--license-override '$($(2)LICENSE_OVERRIDE)') \
	    $(if $($(2)LICENSE_TEXT),--license-text "$($(2)LICENSE_TEXT)") \
	    $(if $($(2)VERSION),--version "$($(2)VERSION)") \
	    $(if $($(2)VERSION_FILE),--version-file "$($(2)VERSION_FILE)") \
	    $(if $($(2)VERSION_MACRO),--version-macro "$($(2)VERSION_MACRO)") \
	    $(if $($(2)DEP_WOLFSSL),--dep-wolfssl "$($(2)DEP_WOLFSSL)") \
	    $(if $($(2)DEP_WOLFCRYPT),--dep-wolfcrypt "$($(2)DEP_WOLFCRYPT)") \
	    $(if $($(2)DEP_OPENSSL),--dep-openssl "$($(2)DEP_OPENSSL)") \
	    $(if $($(2)DEP_LIBZ),--dep-libz "$($(2)DEP_LIBZ)") \
	    $(if $($(2)DOCUMENT_NAMESPACE),--document-namespace "$($(2)DOCUMENT_NAMESPACE)") \
	    $(if $($(2)CRYPTO_ONLY),--crypto-only "$($(2)CRYPTO_ONLY)") \
	    $$$$dep_ver \
	    $(if $(or $($(2)GEN),$(GEN_SBOM)),--gen-sbom "$(or $($(2)GEN),$(GEN_SBOM))") \
	    $(if $($(2)CDX_OUT),--cdx-out "$($(2)CDX_OUT)") \
	    $(if $($(2)SPDX_OUT),--spdx-out "$($(2)SPDX_OUT)")
endef

SBOM_TARGET ?= sbom
$(eval $(call wolfssl_compliance_tooling_sbom_rule,$(SBOM_TARGET),SBOM_))
