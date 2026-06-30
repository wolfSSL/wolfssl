# includes append to these:
SUFFIXES =
TESTS =
CLEANFILES =
DISTCLEANFILES =
MAINTAINERCLEANFILES =
bin_PROGRAMS =
noinst_HEADERS =
lib_LTLIBRARIES =
man_MANS =
noinst_LTLIBRARIES =
noinst_PROGRAMS =
include_HEADERS =
nobase_include_HEADERS =
check_PROGRAMS =
EXTRA_HEADERS =
BUILT_SOURCES=
EXTRA_DIST=
dist_doc_DATA=
dist_noinst_SCRIPTS =
noinst_SCRIPTS =
check_SCRIPTS =
noinst_DATA =
ignore_files =
SUBDIRS_OPT =
DIST_SUBDIRS_OPT =

# Serialize the build when Intel QuickAssist is enabled. Concurrent QAT user
# processes (the parallel test binaries that `make -j check` launches) exhaust
# the device's crypto instances and usdm contiguous memory, so the test phase
# must run serially. With the non-recursive build this disables -j for the
# whole invocation, which also matches the QAT driver's build guidance.
if BUILD_INTEL_QA
.NOTPARALLEL:
endif
if BUILD_INTEL_QA_SYNC
.NOTPARALLEL:
endif

# allow supplementary or override flags to be passed at make time:
AM_CPPFLAGS += $(EXTRA_CPPFLAGS)
AM_CFLAGS += $(EXTRA_CFLAGS)
AM_CCASFLAGS += $(EXTRA_CCASFLAGS)
AM_LDFLAGS += $(EXTRA_LDFLAGS)

#includes additional rules from aminclude.am
@INC_AMINCLUDE@
DISTCLEANFILES+= aminclude.am \
             .build_params

CLEANFILES+= ecc-key.der \
             ecc-public-key.der \
             cert.der \
             cert.pem \
             certecc.der \
             certecc.pem \
             certreq.der \
             certreq.pem \
             key.der \
             key.pem \
             ecc-key-pkcs8.der \
             othercert.der \
             othercert.pem \
             pkcs7cert.der \
             pkcs7authEnvelopedDataAES128GCM.der \
             pkcs7authEnvelopedDataAES128GCM_ECDH_SHA1KDF.der \
             pkcs7authEnvelopedDataAES128GCM_KEKRI.der \
             pkcs7authEnvelopedDataAES128GCM_ORI.der \
             pkcs7authEnvelopedDataAES128GCM_PWRI.der \
             pkcs7authEnvelopedDataAES192GCM.der \
             pkcs7authEnvelopedDataAES256GCM.der \
             pkcs7authEnvelopedDataAES256GCM_ECDH_SHA256KDF.der \
             pkcs7authEnvelopedDataAES256GCM_ECDH_SHA256KDF_authAttribs.der \
             pkcs7authEnvelopedDataAES256GCM_ECDH_SHA256KDF_bothAttribs.der \
             pkcs7authEnvelopedDataAES256GCM_ECDH_SHA256KDF_fw_bothAttribs.der \
             pkcs7authEnvelopedDataAES256GCM_ECDH_SHA256KDF_unauthAttribs.der \
             pkcs7authEnvelopedDataAES256GCM_ECDH_SHA512KDF.der \
             pkcs7authEnvelopedDataAES256GCM_ECDH_SHA512KDF_ukm.der \
             pkcs7authEnvelopedDataAES256GCM_firmwarePkgData.der \
             pkcs7authEnvelopedDataAES256GCM_IANDS.der \
             pkcs7authEnvelopedDataAES256GCM_SKID.der \
             pkcs7compressedData_data_zlib.der \
             pkcs7compressedData_firmwarePkgData_zlib.der \
             pkcs7encryptedDataAES128CBC.der \
             pkcs7encryptedDataAES192CBC.der \
             pkcs7encryptedDataAES256CBC_attribs.der \
             pkcs7encryptedDataAES256CBC.der \
             pkcs7encryptedDataAES256CBC_firmwarePkgData.der \
             pkcs7encryptedDataAES256CBC_multi_attribs.der \
             pkcs7encryptedDataDES3.der \
             pkcs7encryptedDataDES.der \
             pkcs7envelopedDataAES256CBC_ECDH.der \
             cmake/wolfssl-config.cmake \
             cmake/wolfssl-config-version.cmake \
             cmake/wolfssl-targets.cmake \
             pkcs7envelopedDataAES128CBC_ECDH_SHA1KDF.der \
             pkcs7envelopedDataAES256CBC_ECDH_SHA256KDF.der \
             pkcs7envelopedDataAES256CBC_ECDH_SHA512KDF.der \
             pkcs7envelopedDataAES256CBC_ECDH_SHA512KDF_ukm.der \
             pkcs7envelopedDataDES3.der \
             pkcs7envelopedDataAES128CBC.der \
             pkcs7envelopedDataAES128CBC_KEKRI.der \
             pkcs7envelopedDataAES128CBC_PWRI.der \
             pkcs7envelopedDataAES128CBC_ORI.der \
             pkcs7envelopedDataAES192CBC.der \
             pkcs7envelopedDataAES256CBC.der \
             pkcs7envelopedDataAES256CBC_IANDS.der \
             pkcs7envelopedDataAES256CBC_SKID.der \
             pkcs7signedData_RSA_SHA.der \
             pkcs7signedData_RSA_SHA_noattr.der \
             pkcs7signedData_RSA_SHA224.der \
             pkcs7signedData_RSA_SHA256.der \
             pkcs7signedData_RSA_SHA256_firmwarePkgData.der \
             pkcs7signedData_RSA_SHA256_custom_contentType.der \
             pkcs7signedData_RSA_SHA256_with_ca_cert.der \
             pkcs7signedData_RSA_SHA256_SKID.der \
             pkcs7signedData_RSA_SHA256_detachedSig.der \
             pkcs7signedData_RSA_SHA384.der \
             pkcs7signedData_RSA_SHA512.der \
             pkcs7signedData_ECDSA_SHA.der \
             pkcs7signedData_ECDSA_SHA_noattr.der \
             pkcs7signedData_ECDSA_SHA224.der \
             pkcs7signedData_ECDSA_SHA256.der \
             pkcs7signedData_ECDSA_SHA256_firmwarePkgData.der \
             pkcs7signedData_ECDSA_SHA256_custom_contentType.der \
             pkcs7signedData_ECDSA_SHA256_SKID.der \
             pkcs7signedData_ECDSA_SHA384.der \
             pkcs7signedData_ECDSA_SHA512.der \
             pkcs7signedFirmwarePkgData_ECDSA_SHA256.der \
             pkcs7signedFirmwarePkgData_ECDSA_SHA256_SKID.der \
             pkcs7signedFirmwarePkgData_ECDSA_SHA256_noattr.der \
             pkcs7signedFirmwarePkgData_RSA_SHA256.der \
             pkcs7signedFirmwarePkgData_RSA_SHA256_SKID.der \
             pkcs7signedFirmwarePkgData_RSA_SHA256_noattr.der \
             pkcs7signedFirmwarePkgData_RSA_SHA256_with_ca_cert.der \
             pkcs7signedCompressedFirmwarePkgData_ECDSA_SHA256.der \
             pkcs7signedCompressedFirmwarePkgData_ECDSA_SHA256_noattr.der \
             pkcs7signedCompressedFirmwarePkgData_RSA_SHA256.der \
             pkcs7signedCompressedFirmwarePkgData_RSA_SHA256_noattr.der \
             pkcs7signedEncryptedFirmwarePkgData_RSA_SHA256.der \
             pkcs7signedEncryptedFirmwarePkgData_RSA_SHA256_noattr.der \
             pkcs7signedEncryptedFirmwarePkgData_ECDSA_SHA256.der \
             pkcs7signedEncryptedFirmwarePkgData_ECDSA_SHA256_noattr.der \
             pkcs7signedEncryptedCompressedFirmwarePkgData_ECDSA_SHA256.der \
             pkcs7signedEncryptedCompressedFirmwarePkgData_ECDSA_SHA256_noattr.der \
             pkcs7signedEncryptedCompressedFirmwarePkgData_RSA_SHA256.der \
             pkcs7signedEncryptedCompressedFirmwarePkgData_RSA_SHA256_noattr.der \
             tests/test-log-dump-to-file.txt \
             tests/bio_write_test.txt \
             tests/cert_cache.tmp \
             certeccrsa.der \
             certeccrsa.pem \
             ecc-key.pem \
             test-write-dhparams.pem \
             MyKeyLog.txt

exampledir = $(docdir)/example
dist_example_DATA=

ACLOCAL_AMFLAGS= -I m4

EXTRA_DIST+= .cyignore
EXTRA_DIST+= wolfssl.vcproj
EXTRA_DIST+= wolfssl.vcxproj
EXTRA_DIST+= wolfssl-VS2022.vcxproj
EXTRA_DIST+= wolfssl64.sln
EXTRA_DIST+= valgrind-error.sh
EXTRA_DIST+= valgrind-bash.supp
EXTRA_DIST+= fips-hash.sh
EXTRA_DIST+= fips-hash-offline.sh
EXTRA_DIST+= .github/scripts/check-source-text.sh
EXTRA_DIST+= gencertbuf.pl
EXTRA_DIST+= README.md
EXTRA_DIST+= README-async.md
EXTRA_DIST+= README
EXTRA_DIST+= ChangeLog.md
EXTRA_DIST+= LICENSING
EXTRA_DIST+= INSTALL
EXTRA_DIST+= LPCExpresso.cproject
EXTRA_DIST+= LPCExpresso.project
EXTRA_DIST+= resource.h wolfssl.rc
EXTRA_DIST+= CMakeLists.txt
EXTRA_DIST+= CMakePresets.json
EXTRA_DIST+= CMakeSettings.json
EXTRA_DIST+= m4/ax_atomic.m4

include cmake/include.am
include wrapper/include.am
include wolfssl/include.am
include certs/include.am
include doc/include.am
include Docker/include.am

include src/include.am
include support/include.am
include wolfcrypt/benchmark/include.am
include wolfcrypt/src/include.am
include wolfcrypt/test/include.am
include examples/include.am
include testsuite/include.am
include tests/include.am
include sslSniffer/sslSnifferTest/include.am
include debian/include.am
include rpm/include.am
include linuxkm/include.am
include bsdkm/include.am
include zephyr/include.am
include RTOS/nuttx/include.am

# Exclude references to non-DFSG sources from build files
if !BUILD_DISTRO
include mqx/util_lib/Sources/include.am
include mqx/wolfcrypt_benchmark/Sources/include.am
include mqx/wolfcrypt_test/Sources/include.am
include mqx/wolfssl/include.am
include mqx/wolfssl_client/Sources/include.am
include mplabx/include.am
include mplabx/wolfcrypt_benchmark.X/nbproject/include.am
include mplabx/wolfcrypt_test.X/nbproject/include.am
include mplabx/wolfssl.X/nbproject/include.am
include mcapi/include.am
include mcapi/wolfcrypt_mcapi.X/nbproject/include.am
include mcapi/wolfcrypt_test.X/nbproject/include.am
include mcapi/wolfssl.X/nbproject/include.am
include mcapi/zlib.X/nbproject/include.am
include tirtos/include.am
include IDE/include.am
endif
include scripts/include.am

if BUILD_LINUXKM
    # rather than setting $SUBDIRS here directly, we set an auxiliary variable.
    # autotools sees the SUBDIRS assignment here even if BUILD_LINUXKM is false,
    # at least for purposes of recursing for "make distdir", which we don't want to happen.
    SUBDIRS_OPT += linuxkm
    DIST_SUBDIRS_OPT += linuxkm

    export build_triplet host_triplet CC AS LD \
        KERNEL_ROOT KERNEL_ARCH KERNEL_EXTRA_CFLAGS \
        EXTRA_CFLAGS EXTRA_CPPFLAGS EXTRA_CCASFLAGS EXTRA_LDFLAGS \
	AM_CPPFLAGS CPPFLAGS AM_CFLAGS CFLAGS \
        AM_CCASFLAGS CCASFLAGS \
        src_libwolfssl_la_OBJECTS ENABLED_CRYPT_TESTS ENABLED_LINUXKM_LKCAPI_REGISTER \
        ENABLED_LINUXKM_PIE ENABLED_ASM \
        CFLAGS_FPU_DISABLE CFLAGS_FPU_ENABLE CFLAGS_SIMD_DISABLE CFLAGS_SIMD_ENABLE \
        CFLAGS_AUTO_VECTORIZE_DISABLE CFLAGS_AUTO_VECTORIZE_ENABLE \
        ASFLAGS_FPU_DISABLE_SIMD_ENABLE ASFLAGS_FPU_ENABLE_SIMD_DISABLE \
        ASFLAGS_FPUSIMD_DISABLE ASFLAGS_FPUSIMD_ENABLE ENABLED_KERNEL_BENCHMARKS \
        FIPS_FLAVOR

module:
	+$(MAKE) -C linuxkm module

module-update-fips-hash:
	+$(MAKE) -C linuxkm module-update-fips-hash

module-with-matching-fips-hash:
	+$(MAKE) -C linuxkm module-with-matching-fips-hash

module-with-matching-fips-hash-no-sign:
	+$(MAKE) -C linuxkm module-with-matching-fips-hash-no-sign

clean_module:
	+$(MAKE) -C linuxkm clean

install_module modules_install:
	+$(MAKE) -C linuxkm modules_install

endif

if BUILD_BSDKM
    SUBDIRS_OPT += bsdkm
    DIST_SUBDIRS_OPT += bsdkm

.MAKE.EXPORTED = build_triplet host_triplet CC AS LD \
        KERNEL_ROOT BSDKM_EXPORT_SYMS KERNEL_EXTRA_CFLAGS \
        EXTRA_CFLAGS EXTRA_CPPFLAGS EXTRA_CCASFLAGS EXTRA_LDFLAGS \
        AM_CPPFLAGS CPPFLAGS AM_CFLAGS CFLAGS \
        AM_CCASFLAGS CCASFLAGS \
        src_libwolfssl_la_OBJECTS ENABLED_CRYPT_TESTS ENABLED_BSDKM_REGISTER \
        ENABLED_ASM ENABLED_INTELASM ENABLED_AESNI ENABLED_AESNI_WITH_AVX \
        ENABLED_KERNEL_BENCHMARKS
endif


if USE_VALGRIND
TESTS_ENVIRONMENT=./valgrind-error.sh
endif

TEST_EXTENSIONS=.test
TESTS += $(check_PROGRAMS)

check_SCRIPTS+= $(dist_noinst_SCRIPTS)
TESTS += $(check_SCRIPTS)

##############################################################################
# Out-of-tree ("VPATH") build support for "make check".
#
# The test programs (testsuite, tests/unit.test) and the example client and
# server binaries, as well as the shell-script tests under scripts/, locate
# their read-only inputs using paths relative to the working directory:
# certificates under certs/, TLS test-configuration files under tests/, sniffer
# captures and helpers under scripts/, and the top-level "input"/"quit" files.
# ChangeToWolfRoot() (wolfssl/test.h) walks up from the working directory
# looking for certs/dh2048.pem to anchor these relative paths.
#
# For an in-tree build that data is already present in the build directory, but
# for an out-of-tree build it exists only in the source tree.  Symlink it into
# the build tree so the tests can find it.  This is driven by a stamp file in
# BUILT_SOURCES so it runs once, before anything else, for "make", "make all"
# and "make check".  It is a no-op for in-tree builds.
#
# The setup and the distclean cleanup use rm -rf: a --private-dir run of
# .github/scripts/parallel-make-check.py replaces the certs symlink with a
# private directory copy, which rm -f would not remove.  The recipe body
# runs under set -e so a failed symlink aborts the build instead of being
# stamped complete.
##############################################################################
BUILT_SOURCES += wolfssl-test-data.stamp

wolfssl-test-data.stamp:
	$(AM_V_at)set -e; \
	if test "$(abs_top_srcdir)" != "$(abs_top_builddir)"; then \
		$(MKDIR_P) tests scripts examples; \
		for f in certs input quit; do \
			rm -rf "$$f"; \
			$(LN_S) "$(abs_top_srcdir)/$$f" "$$f"; \
		done; \
		rm -f examples/crypto_policies; \
		$(LN_S) "$(abs_top_srcdir)/examples/crypto_policies" \
			examples/crypto_policies; \
		for f in "$(abs_top_srcdir)"/tests/*.conf \
		         "$(abs_top_srcdir)"/tests/*.cnf \
		         "$(abs_top_srcdir)"/tests/TXT_DB.txt; do \
			test -e "$$f" || continue; \
			b=`basename "$$f"`; \
			rm -f "tests/$$b"; \
			$(LN_S) "$$f" "tests/$$b"; \
		done; \
		for f in "$(abs_top_srcdir)"/scripts/*.pcap \
		         "$(abs_top_srcdir)"/scripts/*.out \
		         "$(abs_top_srcdir)"/scripts/*.sslkeylog \
		         "$(abs_top_srcdir)"/scripts/multi-msg-record.py; do \
			test -e "$$f" || continue; \
			b=`basename "$$f"`; \
			rm -f "scripts/$$b"; \
			$(LN_S) "$$f" "scripts/$$b"; \
		done; \
	fi
	$(AM_V_at)touch $@

DISTCLEANFILES += wolfssl-test-data.stamp

# Remove the symlinks created for out-of-tree builds.  Gated on
# srcdir != builddir so an in-tree build never touches the real source files.
distclean-local:
	$(AM_V_at)if test "$(abs_top_srcdir)" != "$(abs_top_builddir)"; then \
		rm -rf certs input quit; \
		rm -f tests/*.conf tests/*.cnf tests/TXT_DB.txt; \
		rm -f scripts/*.pcap scripts/*.out scripts/*.sslkeylog \
		      scripts/multi-msg-record.py; \
		rm -f examples/crypto_policies; \
	fi

test: check
@BUILD_EXAMPLE_SERVERS_TRUE@tests/unit.log: testsuite/testsuite.log
@BUILD_EXAMPLE_SERVERS_TRUE@scripts/unit.log: testsuite/testsuite.log

DISTCLEANFILES+= wolfssl-config

MAINTAINERCLEANFILES+= wolfssl/wolfcrypt/async.h
MAINTAINERCLEANFILES+= wolfssl/wolfcrypt/fips.h
MAINTAINERCLEANFILES+= wolfssl/wolfcrypt/port/cavium/cavium_nitrox.h
MAINTAINERCLEANFILES+= wolfssl/wolfcrypt/port/intel/quickassist.h
MAINTAINERCLEANFILES+= wolfssl/wolfcrypt/port/intel/quickassist_mem.h

SUBDIRS=$(SUBDIRS_OPT)
DIST_SUBDIRS=$(DIST_SUBDIRS_OPT)

maintainer-clean-local:
	-rm Makefile.in
	-rm aclocal.m4
	-rm build-aux/compile
	-rm build-aux/config.guess
	-rm build-aux/config.sub
	-rm build-aux/depcomp
	-rm build-aux/install-sh
	-rm build-aux/ltmain.sh
	-rm build-aux/missing
	-rmdir build-aux
	-rm configure
	-rm config.log
	-rm config.status
	-rm config.in
	-rm m4/libtool.m4
	-rm m4/ltoptions.m4
	-rm m4/ltsugar.m4
	-rm m4/ltversion.m4
	-rm m4/lt~obsolete.m4
	-rm support/wolfssl.pc
	find . -type f -name '*~' -exec rm -f '{}' \;
	-rm -f @PACKAGE@-*.tar.gz
	-rm -f @PACKAGE@-*.rpm

# !!!! first line of rule has to start with a hard (real) tab, not spaces
egs:
	$(MAKE) examples/client/client; \
	$(MAKE) examples/echoclient/echoclient;\
	$(MAKE) examples/server/server; \
	$(MAKE) examples/echoserver/echoserver;

wc_egs:
	$(MAKE) wolfcrypt/test/testwolfcrypt; \
	$(MAKE) wolfcrypt/benchmark/benchmark;

install-exec-local:	install-generic-config

install-generic-config:
	$(mkinstalldirs) $(DESTDIR)$(bindir)
	$(INSTALL_SCRIPT) @GENERIC_CONFIG@ $(DESTDIR)$(bindir)

uninstall-local:
	-rm -f $(DESTDIR)$(bindir)/@GENERIC_CONFIG@

merge-clean:
	@find ./ | $(GREP) \.gcda | xargs rm -f
	@find ./ | $(GREP) \.gcno | xargs rm -f
	@find ./ | $(GREP) \.gz | xargs rm -f
	@find ./ | $(GREP) \.orig | xargs rm -f
	@find ./ | $(GREP) \.rej | xargs rm -f
	@find ./ | $(GREP) \.rpm | xargs rm -f
	@find ./ | $(GREP) \.THIS | xargs rm -f
	@find ./ | $(GREP) \.OTHER | xargs rm -f
	@find ./ | $(GREP) \.BASE | xargs rm -f
	@find ./ | $(GREP) \~$$ | xargs rm -f

%.o: %.cu
	$(NVCC) -dc $(CUDAFLAGS) -o $@ $<

.cu.lo:
	$(LIBTOOL) --tag=CC --mode=compile $(COMPILE) --compile -o $@ $< -static

# SBOM generation (CRA compliance)
SBOM_CDX     = wolfssl-$(PACKAGE_VERSION).cdx.json
SBOM_SPDX    = wolfssl-$(PACKAGE_VERSION).spdx.json
SBOM_SPDX_TV = wolfssl-$(PACKAGE_VERSION).spdx
sbomdir      = $(datadir)/doc/$(PACKAGE)

# Shared-library / Mach-O basenames in priority order (versioned first).
# Both `sbom:` and `bomsh:` glob for these under their own search prefixes;
# adding a new platform-specific dynamic-library extension here updates
# both targets at once.  Static (.a) and Windows (.dll/.lib) variants are
# listed inline at each call-site because their ordering and prefixes
# differ between the install tree and the build tree.
WOLFSSL_LIB_DSO_BASENAMES = \
    libwolfssl.so.[0-9]* \
    libwolfssl.so \
    libwolfssl.[0-9]*.dylib \
    libwolfssl.dylib

.PHONY: sbom install-sbom uninstall-sbom

# Stage a `make install` into a private tree, discover the installed library
# artifact (shared or static, ELF/Mach-O/PE), hash it, generate SPDX+CDX,
# validate the SPDX, then convert to tag-value.  The staging tree is removed
# unconditionally via `trap`, even if any step fails.  Honors SOURCE_DATE_EPOCH
# for reproducible builds (set by the recipe to `git log -1 --format=%ct` when
# unset and a git tree is available).
#
# User-overridable variables:
#   SBOM_LICENSE_OVERRIDE  SPDX expression to use instead of the GPL ID
#                          parsed from LICENSING (e.g. for commercial
#                          licensees: LicenseRef-wolfSSL-Commercial).
#   SBOM_LICENSE_TEXT      Path to the actual licence text for any
#                          LicenseRef-* in SBOM_LICENSE_OVERRIDE.  Required
#                          for SPDX 2.3 conformance whenever a custom
#                          LicenseRef is in use; `make sbom` exits with an
#                          error if it is missing.
#   SBOM_DOCUMENT_NAMESPACE Override the SPDX documentNamespace.  Default
#                          is a deterministic urn:uuid (SPDX 2.3 sec. 6.5
#                          requires only uniqueness, not resolvability).
#                          Downstream packagers re-hosting the SBOM under
#                          their own URL should set this to a URI they
#                          actually serve (e.g.
#                          https://example.com/sbom/wolfssl-X.Y.Z.spdx.json).
#   SBOM_DEP_VERSIONS      Space-separated KEY=VERSION list forwarded to
#                          gen-sbom as repeated --dep-version flags (KEY is
#                          one of the known deps, e.g. liboqs / libz).  Use
#                          this on build/packaging hosts that lack the dep's
#                          pkg-config .pc file, where version detection would
#                          otherwise fall back to NOASSERTION (SPDX) / an
#                          omitted version+purl (CycloneDX).  Example:
#                          make sbom SBOM_DEP_VERSIONS='liboqs=0.10.0 libz=1.3.1'.
#   SBOM_LIB_OVERRIDE      Absolute path to the library artefact whose
#                          SHA-256 should land in the SBOM, INSTEAD of
#                          discovering one via a private staging install.
#                          Set by `make bomsh` so the SBOM hash and the
#                          OmniBOR enrichment refer to the SAME bomsh-
#                          traced binary; without this override `make
#                          sbom` would re-link via `make install` and
#                          hash a different artefact than `bomsh_sbom.py`
#                          fingerprints, leaving the SHA-256 in
#                          `checksums[]` and the gitoid in `externalRefs`
#                          describing two unrelated files.
sbom:
	@if test -z "$(PYTHON3)"; then \
	    echo ""; \
	    echo "ERROR: 'python3' not found in PATH. Cannot generate SBOM."; \
	    echo ""; \
	    exit 1; \
	fi
	@if test -z "$(PYSPDXTOOLS)"; then \
	    echo ""; \
	    echo "ERROR: 'pyspdxtools' not found in PATH. Cannot validate SBOM."; \
	    echo "       Install: pip install spdx-tools"; \
	    echo ""; \
	    exit 1; \
	fi
	@rm -rf $(abs_builddir)/_sbom_staging
	@set -e; \
	trap 'rm -rf $(abs_builddir)/_sbom_staging' EXIT INT TERM HUP; \
	if test -n "$(SBOM_LIB_OVERRIDE)"; then \
	    if test ! -f "$(SBOM_LIB_OVERRIDE)"; then \
	        echo ""; \
	        echo "ERROR: SBOM_LIB_OVERRIDE=$(SBOM_LIB_OVERRIDE) does not exist."; \
	        echo ""; \
	        exit 1; \
	    fi; \
	    sbom_lib="$(SBOM_LIB_OVERRIDE)"; \
	else \
	    $(MAKE) install DESTDIR=$(abs_builddir)/_sbom_staging; \
	    sbom_lib=""; \
	    for lib in \
	        $(addprefix "$(abs_builddir)/_sbom_staging$(libdir)"/,$(WOLFSSL_LIB_DSO_BASENAMES)) \
	        "$(abs_builddir)/_sbom_staging$(libdir)"/libwolfssl.dll \
	        "$(abs_builddir)/_sbom_staging$(libdir)"/libwolfssl.dll.a \
	        "$(abs_builddir)/_sbom_staging$(libdir)"/libwolfssl.lib \
	        "$(abs_builddir)/_sbom_staging$(libdir)"/wolfssl.lib \
	        "$(abs_builddir)/_sbom_staging$(libdir)"/libwolfssl.a; do \
	        if test -f "$$lib"; then sbom_lib="$$lib"; break; fi; \
	    done; \
	    if test -z "$$sbom_lib"; then \
	        echo ""; \
	        echo "ERROR: No installed wolfSSL library artifact found for SBOM."; \
	        echo "       Searched in $(abs_builddir)/_sbom_staging$(libdir)"; \
	        echo "       (configure with --enable-shared or --enable-static)"; \
	        echo ""; \
	        exit 1; \
	    fi; \
	fi; \
	echo "SBOM: hashing $$sbom_lib"; \
	if test -z "$${SOURCE_DATE_EPOCH:-}" && test -n "$(GIT)" && \
	   $(GIT) -C "$(srcdir)" rev-parse --git-dir >/dev/null 2>&1; then \
	    sde=`$(GIT) -C "$(srcdir)" log -1 --format=%ct 2>/dev/null`; \
	    if test -n "$$sde"; then \
	        SOURCE_DATE_EPOCH="$$sde"; \
	        export SOURCE_DATE_EPOCH; \
	    fi; \
	fi; \
	$(PYTHON3) $(srcdir)/scripts/gen-sbom \
	    --name $(PACKAGE) \
	    --version $(PACKAGE_VERSION) \
	    --license-file $(srcdir)/LICENSING \
	    $(if $(SBOM_LICENSE_OVERRIDE),--license-override '$(SBOM_LICENSE_OVERRIDE)') \
	    $(if $(SBOM_LICENSE_TEXT),--license-text '$(SBOM_LICENSE_TEXT)') \
	    $(if $(SBOM_DOCUMENT_NAMESPACE),--document-namespace '$(SBOM_DOCUMENT_NAMESPACE)') \
	    --options-h $(abs_builddir)/wolfssl/options.h \
	    --lib "$$sbom_lib" \
	    --dep-libz $(ENABLED_LIBZ) \
	    --dep-liboqs $(ENABLED_LIBOQS) \
	    $(foreach dv,$(SBOM_DEP_VERSIONS),--dep-version '$(dv)') \
	    --cdx-out $(abs_builddir)/$(SBOM_CDX) \
	    --spdx-out $(abs_builddir)/$(SBOM_SPDX); \
	$(PYSPDXTOOLS) --infile $(abs_builddir)/$(SBOM_SPDX) \
	    --outfile $(abs_builddir)/$(SBOM_SPDX_TV)

install-sbom: sbom
	$(MKDIR_P) $(DESTDIR)$(sbomdir)
	$(INSTALL_DATA) $(SBOM_CDX) $(DESTDIR)$(sbomdir)/
	$(INSTALL_DATA) $(SBOM_SPDX) $(DESTDIR)$(sbomdir)/
	$(INSTALL_DATA) $(SBOM_SPDX_TV) $(DESTDIR)$(sbomdir)/

uninstall-sbom:
	-rm -f $(DESTDIR)$(sbomdir)/$(SBOM_CDX)
	-rm -f $(DESTDIR)$(sbomdir)/$(SBOM_SPDX)
	-rm -f $(DESTDIR)$(sbomdir)/$(SBOM_SPDX_TV)

CLEANFILES += $(SBOM_CDX) $(SBOM_SPDX) $(SBOM_SPDX_TV)

# Security advisory generation (CSAF 2.0 + CycloneDX 1.6 VEX)
#
# `make advisory` is a thin wrapper around scripts/gen-advisory: it feeds the
# script the canonical advisory single-source-of-truth under advisories/ and is
# byte-for-byte interchangeable with running the script by hand.  Equivalent
# invocations:
#
#     make advisory
#     python3 scripts/gen-advisory                       # uses the same defaults
#     python3 scripts/gen-advisory \
#         --records-dir advisories/records \
#         --vex-overlay advisories/vex-overlay.json \
#         --out-dir advisories/out
#
# Inputs  (tracked in git): advisories/records/*.json + advisories/vex-overlay.json
# Outputs (build artifacts): advisories/out/*.{csaf,cdx}.json
ADVISORY_RECORDS_DIR = $(srcdir)/advisories/records
ADVISORY_OVERLAY     = $(srcdir)/advisories/vex-overlay.json
ADVISORY_OUT_DIR     = $(abs_builddir)/advisories/out
advisorydir          = $(datadir)/doc/$(PACKAGE)/advisories

.PHONY: advisory install-advisory uninstall-advisory

# Generate one CSAF + one CycloneDX VEX document per CVE record.  Honors
# SOURCE_DATE_EPOCH for reproducible output (set from the last git commit when
# unset and a git tree is available), exactly like `make sbom`.
advisory:
	@if test -z "$(PYTHON3)"; then \
	    echo ""; \
	    echo "ERROR: 'python3' not found in PATH. Cannot generate advisories."; \
	    echo ""; \
	    exit 1; \
	fi
	@set -e; \
	if test -z "$${SOURCE_DATE_EPOCH:-}" && test -n "$(GIT)" && \
	   $(GIT) -C "$(srcdir)" rev-parse --git-dir >/dev/null 2>&1; then \
	    sde=`$(GIT) -C "$(srcdir)" log -1 --format=%ct 2>/dev/null`; \
	    if test -n "$$sde"; then \
	        SOURCE_DATE_EPOCH="$$sde"; \
	        export SOURCE_DATE_EPOCH; \
	    fi; \
	fi; \
	$(PYTHON3) $(srcdir)/scripts/gen-advisory \
	    --records-dir $(ADVISORY_RECORDS_DIR) \
	    --vex-overlay $(ADVISORY_OVERLAY) \
	    --out-dir $(ADVISORY_OUT_DIR)

install-advisory: advisory
	$(MKDIR_P) $(DESTDIR)$(advisorydir)
	@for f in $(ADVISORY_OUT_DIR)/*.json; do \
	    test -f "$$f" || continue; \
	    echo " $(INSTALL_DATA) $$f $(DESTDIR)$(advisorydir)/"; \
	    $(INSTALL_DATA) "$$f" $(DESTDIR)$(advisorydir)/; \
	done

uninstall-advisory:
	-rm -f $(DESTDIR)$(advisorydir)/*.csaf.json
	-rm -f $(DESTDIR)$(advisorydir)/*.cdx.json

CLEANFILES += advisories/out/*.csaf.json advisories/out/*.cdx.json

# Ship the advisory generator inputs in the dist tarball so a downstream
# consumer can `./configure && make advisory` from a release.  The per-CVE
# records are copied via dist-hook (glob) rather than listed in EXTRA_DIST so
# a newly-added record ships automatically: a hardcoded list silently drops
# new records from `make dist`, and the omission only surfaces as a failing
# downstream `make advisory`.
EXTRA_DIST += advisories/vex-overlay.json

dist-hook:
	$(MKDIR_P) $(distdir)/advisories/records
	@for f in $(srcdir)/advisories/records/*.json; do \
	    test -f "$$f" || continue; \
	    cp -p "$$f" $(distdir)/advisories/records/; \
	done

# Bomsh (OmniBOR build artifact tracing + SBOM enrichment)
BOMSH_RAWLOG_BASE      = $(abs_builddir)/bomsh_raw_logfile
BOMSH_RAWLOG           = $(BOMSH_RAWLOG_BASE).sha1
BOMSH_CONF             = $(abs_builddir)/_bomsh.conf
BOMSH_OMNIBORDIR       = $(abs_builddir)/omnibor
BOMSH_SPDX_OUT         = omnibor.wolfssl-$(PACKAGE_VERSION).spdx.json
bomshdir          = $(datadir)/doc/$(PACKAGE)

.PHONY: bomsh install-bomsh uninstall-bomsh

# Self-contained: the traced rebuild also regenerates the SBOM, so users
# can run `make bomsh` directly without first running `make sbom`.  This is
# also what makes the combined workflow correct: `make sbom` writes the SPDX,
# but `make bomsh` issues `make clean` (which removes it via CLEANFILES), so
# the only reliable way to enrich is to regenerate after the traced build.
#
# After the traced rebuild we discover the bomsh-traced library in
# $(abs_builddir)/src/.libs/ and pass it to the nested `make sbom` call as
# SBOM_LIB_OVERRIDE.  Without the override `make sbom` would `make install
# DESTDIR=...` into a private tree, which triggers a libtool relink and
# produces a binary whose SHA-256 differs from the one bomtrace3 traced.
# That left the gitoid in `externalRefs` (which IS for the traced binary)
# and the SHA-256 in `checksums[]` (which was NOT) describing two different
# files in the same SPDX document.  With the override they describe the
# same artefact, which is the invariant any auditor reading the document
# expects.
bomsh:
	@if test -z "$(BOMTRACE3)"; then \
	    echo ""; \
	    echo "ERROR: 'bomtrace3' not found in PATH. Cannot generate OmniBOR data."; \
	    echo "       Build bomtrace3 from: https://github.com/omnibor/bomsh"; \
	    echo ""; \
	    exit 1; \
	fi
	@if test -z "$(BOMSH_CREATE_BOM)"; then \
	    echo ""; \
	    echo "ERROR: 'bomsh_create_bom.py' not found in PATH. Cannot process OmniBOR data."; \
	    echo "       Install from: https://github.com/omnibor/bomsh"; \
	    echo ""; \
	    exit 1; \
	fi
	$(MAKE) clean
	@printf 'raw_logfile=%s\n' '$(BOMSH_RAWLOG_BASE)' > '$(BOMSH_CONF)'
	$(BOMTRACE3) -c '$(BOMSH_CONF)' $(MAKE)
	$(BOMSH_CREATE_BOM) -r '$(BOMSH_RAWLOG)' -b '$(BOMSH_OMNIBORDIR)'
	@set -e; \
	bomsh_artifact=""; \
	for lib in \
	    $(addprefix "$(abs_builddir)/src/.libs"/,$(WOLFSSL_LIB_DSO_BASENAMES)) \
	    "$(abs_builddir)/src/.libs/libwolfssl.a" \
	    "$(abs_builddir)/src/libwolfssl.a"; do \
	    if test -f "$$lib"; then bomsh_artifact="$$lib"; break; fi; \
	done; \
	if test -z "$$bomsh_artifact"; then \
	    echo "NOTE: no built libwolfssl artifact found in $(abs_builddir)/src/.libs/"; \
	    echo "      OmniBOR graph produced; SBOM regeneration + SPDX"; \
	    echo "      enrichment skipped."; \
	    exit 0; \
	fi; \
	echo "bomsh: traced binary -> $$bomsh_artifact"; \
	$(MAKE) sbom SBOM_LIB_OVERRIDE="$$bomsh_artifact"; \
	if test -z "$(BOMSH_SBOM)"; then \
	    echo "NOTE: bomsh_sbom.py not in PATH; skipping SPDX enrichment."; \
	    echo "      The OmniBOR graph in $(BOMSH_OMNIBORDIR) is still produced."; \
	    echo "      The base SBOM in $(SBOM_SPDX) already hashes the bomsh-traced binary."; \
	    exit 0; \
	fi; \
	echo "Enriching SPDX with OmniBOR ExternalRefs (artifact: $$bomsh_artifact)..."; \
	$(BOMSH_SBOM) \
	    -b '$(BOMSH_OMNIBORDIR)' \
	    -i '$(abs_builddir)/$(SBOM_SPDX)' \
	    -f "$$bomsh_artifact" \
	    -s spdx-json \
	    -O '$(abs_builddir)'

install-bomsh: bomsh
	$(MKDIR_P) '$(DESTDIR)$(bomshdir)/omnibor'
	@if test -d '$(BOMSH_OMNIBORDIR)'; then \
	    cp -R '$(BOMSH_OMNIBORDIR)/.' '$(DESTDIR)$(bomshdir)/omnibor/'; \
	fi
	@if test -f '$(abs_builddir)/$(BOMSH_SPDX_OUT)'; then \
	    $(INSTALL_DATA) '$(abs_builddir)/$(BOMSH_SPDX_OUT)' '$(DESTDIR)$(bomshdir)/'; \
	fi

uninstall-bomsh:
	-rm -rf '$(DESTDIR)$(bomshdir)/omnibor'
	-rm -f '$(DESTDIR)$(bomshdir)/$(BOMSH_SPDX_OUT)'

CLEANFILES += $(BOMSH_RAWLOG) $(BOMSH_RAWLOG_BASE).sha256 $(BOMSH_CONF) $(BOMSH_SPDX_OUT)

# Hook SBOM/Bomsh cleanup into `make uninstall` so packagers don't leave
# stale artefacts behind after install-sbom/install-bomsh.  uninstall-sbom
# and uninstall-bomsh use `rm -f` / `rm -rf` so they are idempotent and
# safe whether or not those targets were ever run.  Depending on them
# rather than duplicating their bodies keeps the cleanup paths in lock
# step with install-sbom/install-bomsh.
uninstall-hook: uninstall-sbom uninstall-bomsh uninstall-advisory
