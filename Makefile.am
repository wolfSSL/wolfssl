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

test: check
tests/unit.log: testsuite/testsuite.log
scripts/unit.log: testsuite/testsuite.log

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
	echo "SBOM: hashing $$sbom_lib"; \
	if test -z "$${SOURCE_DATE_EPOCH:-}" && test -n "$(GIT)" && \
	   $(GIT) -C "$(srcdir)" rev-parse --git-dir >/dev/null 2>&1; then \
	    SOURCE_DATE_EPOCH=`$(GIT) -C "$(srcdir)" log -1 --format=%ct 2>/dev/null || echo`; \
	    export SOURCE_DATE_EPOCH; \
	fi; \
	$(PYTHON3) $(srcdir)/scripts/gen-sbom \
	    --name $(PACKAGE) \
	    --version $(PACKAGE_VERSION) \
	    --license-file $(srcdir)/LICENSING \
	    --license-override '$(SBOM_LICENSE_OVERRIDE)' \
	    --license-text '$(SBOM_LICENSE_TEXT)' \
	    --options-h $(abs_builddir)/wolfssl/options.h \
	    --lib "$$sbom_lib" \
	    --dep-libz $(ENABLED_LIBZ) \
	    --dep-liboqs $(ENABLED_LIBOQS) \
	    --git '$(GIT)' \
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

# Bomsh (OmniBOR build artifact tracing + SBOM enrichment)
BOMSH_RAWLOG_BASE = $(abs_builddir)/bomsh_raw_logfile
BOMSH_RAWLOG      = $(BOMSH_RAWLOG_BASE).sha1
BOMSH_CONF        = $(abs_builddir)/_bomsh.conf
BOMSH_OMNIBORDIR  = $(abs_builddir)/omnibor
BOMSH_SPDX_OUT    = omnibor.wolfssl-$(PACKAGE_VERSION).spdx.json
bomshdir          = $(datadir)/doc/$(PACKAGE)

.PHONY: bomsh install-bomsh uninstall-bomsh

# Self-contained: the traced rebuild also regenerates the SBOM, so users
# can run `make bomsh` directly without first running `make sbom`.  This is
# also what makes the combined workflow correct: `make sbom` writes the SPDX,
# but `make bomsh` issues `make clean` (which removes it via CLEANFILES), so
# the only reliable way to enrich is to regenerate after the traced build.
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
	$(MAKE) sbom
	@if test -z "$(BOMSH_SBOM)"; then \
	    echo "NOTE: bomsh_sbom.py not in PATH; skipping SPDX enrichment."; \
	    echo "      The OmniBOR graph in $(BOMSH_OMNIBORDIR) is still produced."; \
	    exit 0; \
	fi; \
	bomsh_artifact=""; \
	for lib in \
	    $(addprefix $(abs_builddir)/src/.libs/,$(WOLFSSL_LIB_DSO_BASENAMES)) \
	    $(abs_builddir)/src/.libs/libwolfssl.a \
	    $(abs_builddir)/src/libwolfssl.a; do \
	    if test -f "$$lib"; then bomsh_artifact="$$lib"; break; fi; \
	done; \
	if test -z "$$bomsh_artifact"; then \
	    echo "NOTE: no built libwolfssl artifact found in $(abs_builddir)/src/.libs/"; \
	    echo "      OmniBOR graph produced; SPDX enrichment skipped."; \
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
	    (cd '$(BOMSH_OMNIBORDIR)' && tar cf - .) | \
	        (cd '$(DESTDIR)$(bomshdir)/omnibor' && tar xf -); \
	fi
	@if test -f '$(abs_builddir)/$(BOMSH_SPDX_OUT)'; then \
	    $(INSTALL_DATA) '$(abs_builddir)/$(BOMSH_SPDX_OUT)' '$(DESTDIR)$(bomshdir)/'; \
	fi

uninstall-bomsh:
	-rm -rf '$(DESTDIR)$(bomshdir)/omnibor'
	-rm -f '$(DESTDIR)$(bomshdir)/$(BOMSH_SPDX_OUT)'

CLEANFILES += $(BOMSH_RAWLOG) $(BOMSH_RAWLOG_BASE).sha256 $(BOMSH_CONF) $(BOMSH_SPDX_OUT)

# Hook SBOM/Bomsh cleanup into `make uninstall` so packagers don't leave
# stale artefacts behind after install-sbom/install-bomsh.  rm -f is
# idempotent, so this is safe whether or not those targets were ever run.
uninstall-hook:
	-rm -f $(DESTDIR)$(sbomdir)/$(SBOM_CDX)
	-rm -f $(DESTDIR)$(sbomdir)/$(SBOM_SPDX)
	-rm -f $(DESTDIR)$(sbomdir)/$(SBOM_SPDX_TV)
	-rm -rf $(DESTDIR)$(bomshdir)/omnibor
	-rm -f $(DESTDIR)$(bomshdir)/$(BOMSH_SPDX_OUT)
