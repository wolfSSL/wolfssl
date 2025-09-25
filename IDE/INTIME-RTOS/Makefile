# Makefile for the INtime wolfSSL library component
#
SWENGENV := $(RMX_SRC_BASE)/tools/swenghg
#
# makefile -- defines the macros, directives and rules necessary to build the
#             wolfSSL library. 
#
# NOTES:
#     1.  This makefile is a "wrapper" makefile for the Visual Studio 80
#         INtime package project.  The makefile provides RCS and component 
#	      release support not provided by the project's native visual Studio
#         makefile.
# 
#     2.  The SWENG environment assumes makefile execution from a Windows NT
#         environment.
#
#     3.  The SWENG environment assumes that a user has Microsoft Network
#         access to the ESO server directories.
#
#     4.  A SWENG makefile makes no assumptions concerning a user's command
#         path.  All command pathnames are explicit.  Furthermore, the
#         directory component of a pathname is defined by a macro that can be
#         overridden at makefile invocation.
#
#         The same cannot be said for MS Developer Studio makefiles -- they
#         assume MSVC and Windows NT commands are in the user's path.
#
#     5.  A SWENG makefile makes no assumptions concerning a user's environment
#         variable definitions.
#
#         The same cannot be said for MS Developer Studio makefiles -- they
#         assume various environment variables are set properly to build their
#         components.
#
#     6.  A SWENG makefile executes standard MKS and MSVC tools.  Other tool
#         sets require additional macro and rule definition. 
#

# Default macros and directives.
#
# NOTES:
#     1.  These files must always be included before all component-specific
#         macros and directives.

.INCLUDE:$(SWENGENV)/macros.wnt
.INCLUDE:$(SWENGENV)/intimemacros.wnt

# Component and version number macros:
#
#     COMPONENT:  The name of the product component built by this makefile.
#                 DUE TO THE IDIOSYNCRATIC NATURE OF RCS, THIS MACRO MUST NOT
#                 CONTAIN ANY SPECIAL CHARACTERS, INCLUDING " " AND "."!  For
#                 example, the macro for the Real-Time Application Loader
#                 could be defined as:
#
#                     COMPONENT := Real_Time_Application_Loader
#
#                 In the SWENG environment, a PRODUCT is the complete software
#                 package sent to a customer (e.g., INtime V1.00).  A PRODUCT
#                 is composed of one or more COMPONENTs (e.g., Real-Time
#                 Application Loader, NTX Library, etc.)
#
#                 When choosing names for new components, ensure that they
#                 are unique.
#
#     VERSION:    The version number associated with the component(s) built
#                 by this makefile.  DUE TO THE IDIOSYNCRATIC NATURE OF RCS,
#                 THIS MACRO MUST NOT CONTAIN ANY SPECIAL CHARACTERS,
#                 INCLUDING " " AND "."!  For example, the macro for version
#                 1.00 is defined:
#
#                        VERSION := 100
#
#     NAME:       A string used to name both the engineering version of the
#                 component built by this makefile and the source files used
#                 to build it.
#
# NOTES:
#     1.  These macros must not be deleted or renamed.  Their values should be
#         modified to match the components built by this makefile.
#
#     2.  The "engineer" target will not complete unless the COMPONENT,
#         VERSION, and NAME macros are defined.

COMPONENT :=    wolfssl_intime
VERSION :=      572
NAME :=		$(COMPONENT)_$(VERSION)

# MS Developer Studio project name and directory macros.
#
#     PROJECT:       The project name for this component.
#
#     SUB_PROJECTS:  The sub-project name(s) for this component.
#
#     TARG_DIR:      The target directory for component files, relative to the
#                    project and sub-project directories (generally, "Debug" or
#                    "Release").
#
#     TARG_TYPE:     The target type for the project and sub-projects
#                    (generally, "Debug" or "Release").
#
# NOTES:
#     1.  These macros must not be deleted or renamed.  Their values should be
#         modified to match the project/directory structure of the component(s)
#         built by this makefile.  Unused macros values should be defined as
#         $(NULL).

PROJECT      := wolfssl
SUB_PROJECTS := $(NULL)
.IF $(DEBUG)
TARG_DIR     := Debug
TARG_TYPE    := Debug
.ELSE
TARG_DIR     := Release
TARG_TYPE    := Release
.END

# MKS make search path for machine-generated files.
#
# NOTES:
#     1.  All machine-generated target files that do not reside in the current
#         working directory require a .SOURCE directive.  Otherwise, a .SOURCE
#         directive is optional (but will improve makefile performance).

.SOURCE.lib: $(TARG_DIR)

# File list macros:
#
#     TARGETS:   The component(s) built by this makefile.  These are the files
#                built by the default rule ("make" or "make all").
#     LOGFILE:   A log file containing revision data for the project members
#                (files) used to build the TARGETS.  The file is built by the
#                "engineer" rule.
#     MAKEFILE:  Makefile used to build the TARGETS (this file).
#     ASM:       Assembly source code files used to build the TARGETS (.asm).
#     C:         C source code files used to build the TARGETS (.c)
#     CPP:       C++ source code files used to build the TARGETS (.cpp).
#     SRCS:      The concatenation of ASM, C, and CPP.
#     HDRS:      Header files used to build the TARGETS (.h, .hpp, .inc).
#     OBJ:       Object files used to build the TARGETS (.obj).
#     DEBRIS:    Machine-generated files to be deleted by the "clean" rule.
#
# NOTES:
#     1.  These macros must not be deleted or renamed.  Their values may be
#         modified to match the files used to build the component(s) associated
#         with this makefile.
#
#     2.  The "engineer" rule will not complete unless the LOGFILE macro is
#         defined.

EXEC_TARGS := libwolfssl572.lib

SRC_TARGS := user_settings.h
TARGETS  := $(EXEC_TARGS)
LOGFILE  := $(PROJECT).txt
MAKEFILE := makefile
ASM      :=
C        :=
CPP      :=
RCFILE	 := 

SRCS     := 
OBJ      :=
CFGS     := 

DEBRIS   := $(LOGFILE) release* debug* *.sdf *.user *.aps *.bak *~

INCL_TARGS := 	wolfssl/callbacks.h \
	wolfssl/certs_test.h \
	wolfssl/crl.h \
	wolfssl/error-ssl.h \
	wolfssl/include.am \
	wolfssl/internal.h \
	wolfssl/ocsp.h \
	wolfssl/options.h \
	wolfssl/options.h.in \
	wolfssl/quic.h \
	wolfssl/sniffer.h \
	wolfssl/sniffer_error.h \
	wolfssl/sniffer_error.rc \
	wolfssl/ssl.h \
	wolfssl/test.h \
	wolfssl/version.h \
	wolfssl/version.h.in \
	wolfssl/wolfio.h \
	wolfssl/openssl/aes.h \
	wolfssl/openssl/asn1.h \
	wolfssl/openssl/asn1t.h \
	wolfssl/openssl/bio.h \
	wolfssl/openssl/bn.h \
	wolfssl/openssl/buffer.h \
	wolfssl/openssl/camellia.h \
	wolfssl/openssl/cmac.h \
	wolfssl/openssl/cms.h \
	wolfssl/openssl/compat_types.h \
	wolfssl/openssl/conf.h \
	wolfssl/openssl/crypto.h \
	wolfssl/openssl/des.h \
	wolfssl/openssl/dh.h \
	wolfssl/openssl/dsa.h \
	wolfssl/openssl/ec.h \
	wolfssl/openssl/ec448.h \
	wolfssl/openssl/ec25519.h \
	wolfssl/openssl/ecdh.h \
	wolfssl/openssl/ecdsa.h \
	wolfssl/openssl/ecdh.h \
	wolfssl/openssl/ecdsa.h \
	wolfssl/openssl/ed448.h \
	wolfssl/openssl/ed25519.h \
	wolfssl/openssl/engine.h \
	wolfssl/openssl/err.h \
	wolfssl/openssl/evp.h \
	wolfssl/openssl/fips_rand.h \
	wolfssl/openssl/hmac.h \
	wolfssl/openssl/include.am \
	wolfssl/openssl/kdf.h \
	wolfssl/openssl/lhash.h \
	wolfssl/openssl/md4.h \
	wolfssl/openssl/md5.h \
	wolfssl/openssl/modes.h \
	wolfssl/openssl/obj_mac.h \
	wolfssl/openssl/objects.h \
	wolfssl/openssl/ocsp.h \
	wolfssl/openssl/opensslconf.h \
	wolfssl/openssl/opensslv.h \
	wolfssl/openssl/ossl_typ.h \
	wolfssl/openssl/pem.h \
	wolfssl/openssl/pkcs7.h \
	wolfssl/openssl/pkcs12.h \
	wolfssl/openssl/rand.h \
	wolfssl/openssl/rc4.h \
	wolfssl/openssl/ripemd.h \
	wolfssl/openssl/rsa.h \
	wolfssl/openssl/sha.h \
	wolfssl/openssl/sha3.h \
	wolfssl/openssl/srp.h \
	wolfssl/openssl/ssl.h \
	wolfssl/openssl/ssl23.h \
	wolfssl/openssl/stack.h \
	wolfssl/openssl/tls1.h \
	wolfssl/openssl/txt_db.h \
	wolfssl/openssl/ui.h \
	wolfssl/openssl/x509.h \
	wolfssl/openssl/x509_vfy.h \
	wolfssl/openssl/x509v3.h \
	wolfssl/wolfcrypt/aes.h \
	wolfssl/wolfcrypt/arc4.h \
	wolfssl/wolfcrypt/asn.h \
	wolfssl/wolfcrypt/asn_public.h \
	wolfssl/wolfcrypt/async.h \
	wolfssl/wolfcrypt/blake2.h \
	wolfssl/wolfcrypt/blake2-impl.h \
	wolfssl/wolfcrypt/blake2-int.h \
	wolfssl/wolfcrypt/camellia.h \
	wolfssl/wolfcrypt/chacha.h \
	wolfssl/wolfcrypt/chacha20_poly1305.h \
	wolfssl/wolfcrypt/cmac.h \
	wolfssl/wolfcrypt/coding.h \
	wolfssl/wolfcrypt/compress.h \
	wolfssl/wolfcrypt/cpuid.h \
	wolfssl/wolfcrypt/cryptocb.h \
	wolfssl/wolfcrypt/curve448.h \
	wolfssl/wolfcrypt/curve25519.h \
	wolfssl/wolfcrypt/des3.h \
	wolfssl/wolfcrypt/dh.h \
	wolfssl/wolfcrypt/dilithium.h \
	wolfssl/wolfcrypt/dsa.h \
	wolfssl/wolfcrypt/ecc.h \
	wolfssl/wolfcrypt/eccsi.h \
	wolfssl/wolfcrypt/ed448.h \
	wolfssl/wolfcrypt/ed25519.h \
	wolfssl/wolfcrypt/error-crypt.h \
	wolfssl/wolfcrypt/ext_kyber.h \
	wolfssl/wolfcrypt/ext_lms.h \
	wolfssl/wolfcrypt/ext_xmss.h \
	wolfssl/wolfcrypt/falcon.h \
	wolfssl/wolfcrypt/fe_448.h \
	wolfssl/wolfcrypt/fe_operations.h \
	wolfssl/wolfcrypt/fips.h \
	wolfssl/wolfcrypt/fips_test.h \
	wolfssl/wolfcrypt/ge_448.h \
	wolfssl/wolfcrypt/ge_operations.h \
	wolfssl/wolfcrypt/hash.h \
	wolfssl/wolfcrypt/hmac.h \
	wolfssl/wolfcrypt/hpke.h \
	wolfssl/wolfcrypt/include.am \
	wolfssl/wolfcrypt/integer.h \
	wolfssl/wolfcrypt/kdf.h \
	wolfssl/wolfcrypt/kyber.h \
	wolfssl/wolfcrypt/lms.h \
	wolfssl/wolfcrypt/logging.h \
	wolfssl/wolfcrypt/md2.h \
	wolfssl/wolfcrypt/md4.h \
	wolfssl/wolfcrypt/md5.h \
	wolfssl/wolfcrypt/mem_track.h \
	wolfssl/wolfcrypt/memory.h \
	wolfssl/wolfcrypt/misc.h \
	wolfssl/wolfcrypt/mpi_class.h \
	wolfssl/wolfcrypt/mpi_superclass.h \
	wolfssl/wolfcrypt/pkcs7.h \
	wolfssl/wolfcrypt/pkcs11.h \
	wolfssl/wolfcrypt/pkcs12.h \
	wolfssl/wolfcrypt/poly1305.h \
	wolfssl/wolfcrypt/pwdbased.h \
	wolfssl/wolfcrypt/random.h \
	wolfssl/wolfcrypt/rc2.h \
	wolfssl/wolfcrypt/ripemd.h \
	wolfssl/wolfcrypt/rsa.h \
	wolfssl/wolfcrypt/sakke.h \
	wolfssl/wolfcrypt/selftest.h \
	wolfssl/wolfcrypt/settings.h \
	wolfssl/wolfcrypt/sha.h \
	wolfssl/wolfcrypt/sha3.h \
	wolfssl/wolfcrypt/sha256.h \
	wolfssl/wolfcrypt/sha512.h \
	wolfssl/wolfcrypt/signature.h \
	wolfssl/wolfcrypt/siphash.h \
	wolfssl/wolfcrypt/sm2.h \
	wolfssl/wolfcrypt/sm3.h \
	wolfssl/wolfcrypt/sm4.h \
	wolfssl/wolfcrypt/sp.h \
	wolfssl/wolfcrypt/sp_int.h \
	wolfssl/wolfcrypt/sphincs.h \
	wolfssl/wolfcrypt/srp.h \
	wolfssl/wolfcrypt/tfm.h \
	wolfssl/wolfcrypt/types.h \
	wolfssl/wolfcrypt/visibility.h \
	wolfssl/wolfcrypt/wc_encrypt.h \
	wolfssl/wolfcrypt/wc_kyber.h \
	wolfssl/wolfcrypt/wc_pkcs11.h \
	wolfssl/wolfcrypt/wc_port.h \
	wolfssl/wolfcrypt/wolfevent.h \
	wolfssl/wolfcrypt/wolfmath.h \
	wolfssl/wolfcrypt/xmss.h \
	wolfssl/wolfcrypt/port/nrf51.h \
	wolfssl/wolfcrypt/port/af_alg/afalg_hash.h \
	wolfssl/wolfcrypt/port/af_alg/wc_afalg.h \
	wolfssl/wolfcrypt/port/aria/aria-crypt.h \
	wolfssl/wolfcrypt/port/aria/aria-cryptocb.h \
	wolfssl/wolfcrypt/port/arm/cryptoCell.h \
	wolfssl/wolfcrypt/port/atmel/atmel.h \
	wolfssl/wolfcrypt/port/autosar/CryIf.h \
	wolfssl/wolfcrypt/port/autosar/Crypto.h \
	wolfssl/wolfcrypt/port/autosar/Csm.h \
	wolfssl/wolfcrypt/port/autosar/StandardTypes.h \
	wolfssl/wolfcrypt/port/caam/caam_driver.h \
	wolfssl/wolfcrypt/port/caam/caam_error.h \
	wolfssl/wolfcrypt/port/caam/caam_qnx.h \
	wolfssl/wolfcrypt/port/caam/wolfcaam.h \
	wolfssl/wolfcrypt/port/caam/wolfcaam_aes.h \
	wolfssl/wolfcrypt/port/caam/wolfcaam_cmac.h \
	wolfssl/wolfcrypt/port/caam/wolfcaam_ecdsa.h \
	wolfssl/wolfcrypt/port/caam/wolfcaam_fsl_nxp.h \
	wolfssl/wolfcrypt/port/caam/wolfcaam_hash.h \
	wolfssl/wolfcrypt/port/caam/wolfcaam_qnx.h \
	wolfssl/wolfcrypt/port/caam/wolfcaam_rsa.h \
	wolfssl/wolfcrypt/port/caam/wolfcaam_seco.h \
	wolfssl/wolfcrypt/port/caam/wolfcaam_sha.h \
	wolfssl/wolfcrypt/port/caam/wolfcaam_x25519.h \
	wolfssl/wolfcrypt/port/cavium/cavium_nitrox.h \
	wolfssl/wolfcrypt/port/cavium/cavium_octeon_sync.h \
	wolfssl/wolfcrypt/port/cypress/psoc6_crypto.h \
	wolfssl/wolfcrypt/port/devcrypto/wc_devcrypto.h \
	wolfssl/wolfcrypt/port/Espressif/esp32-crypt.h \
	wolfssl/wolfcrypt/port/Espressif/esp-sdk-lib.h \
	wolfssl/wolfcrypt/port/intel/quickassist.h \
	wolfssl/wolfcrypt/port/intel/quickassist_mem.h \
	wolfssl/wolfcrypt/port/intel/quickassist_sync.h \
	wolfssl/wolfcrypt/port/iotsafe/iotsafe.h \
	wolfssl/wolfcrypt/port/kcapi/kcapi_dh.h \
	wolfssl/wolfcrypt/port/kcapi/kcapi_ecc.h \
	wolfssl/wolfcrypt/port/kcapi/kcapi_hash.h \
	wolfssl/wolfcrypt/port/kcapi/kcapi_hmac.h \
	wolfssl/wolfcrypt/port/kcapi/kcapi_rsa.h \
	wolfssl/wolfcrypt/port/kcapi/wc_kcapi.h \
	wolfssl/wolfcrypt/port/liboqs/liboqs.h \
	wolfssl/wolfcrypt/port/maxim/maxq10xx.h \
	wolfssl/wolfcrypt/port/nxp/dcp_port.h \
	wolfssl/wolfcrypt/port/nxp/ksdk_port.h \
	wolfssl/wolfcrypt/port/nxp/se050_port.h \
	wolfssl/wolfcrypt/port/pic32/pic32mz-crypt.h \
	wolfssl/wolfcrypt/port/psa/psa.h \
	wolfssl/wolfcrypt/port/Renesas/renesas_cmn.h \
	wolfssl/wolfcrypt/port/Renesas/renesas_sync.h \
	wolfssl/wolfcrypt/port/Renesas/renesas_tsip_types.h \
	wolfssl/wolfcrypt/port/Renesas/renesas-fspsm-crypt.h \
	wolfssl/wolfcrypt/port/Renesas/renesas-fspsm-types.h \
	wolfssl/wolfcrypt/port/Renesas/renesas-tsip-crypt.h \
	wolfssl/wolfcrypt/port/riscv/riscv-64-asm.h \
	wolfssl/wolfcrypt/port/silabs/silabs_aes.h \
	wolfssl/wolfcrypt/port/silabs/silabs_ecc.h \
	wolfssl/wolfcrypt/port/silabs/silabs_hash.h \
	wolfssl/wolfcrypt/port/silabs/silabs_random.h \
	wolfssl/wolfcrypt/port/st/stm32.h \
	wolfssl/wolfcrypt/port/st/stsafe.h \
	wolfssl/wolfcrypt/port/ti/ti-ccm.h \
	wolfssl/wolfcrypt/port/ti/ti-hash.h \
	wolfssl/wolfcrypt/port/xilinx/xil-sha3.h \
	wolfssl/wolfcrypt/port/xilinx/xil-versal-glue.h \
	wolfssl/wolfcrypt/port/xilinx/xil-versal-trng.h


# Default rules.
#
# NOTES:
#     1.  These files must always be included after the macro definitions and
#         before the component-specific rules. 

.INCLUDE:$(SWENGENV)/rules.wnt
.INCLUDE:$(SWENGENV)/intimerules.wnt

# Component-specific rules, including:
#
#     prodeng:  checks TARGETS into an engineering release directory using the
#               "puttarg.ksh" script.
#
# NOTES:
#     1.  The "prodeng" rule must not be renamed or deleted!  It should,
#         however, be modified to reflect the engineering release requirements
#         of the TARGETS.
#
#     2.  Rules for each of the TARGETS should be added here.
#
#     3.  Additional rules may be added as necessary.  Care should be taken so
#         that rules defined in the rules.wnt file are not redefined here.

prodeng: "$(PROD_ENG)/rt/include/wolfssl572/wolfssl" "$(PROD_ENG)/rt/include/wolfssl572/wolfssl/openssl" \
	"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt" "$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port" \
	"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/af_alg" "$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/aria" \
    "$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/arm" "$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/atmel" \
	"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/autosar" "$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/caam" \
	"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/cavium" "$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/cypress" \
	"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/devcrypto" "$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/espressif" \
	"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/intel" "$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/iotsafe" \
	"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/kcapi" "$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/liboqs" \
	"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/maxim" "$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/nxp" \
	"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/pic32" "$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/psa" \
	"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/Renesas" "$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/riscv" \
    "$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/silabs" "$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/st" \
    "$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/ti" "$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/xilinx" \
    "$(PROD_ENG)/rt/lib"
[@
for f in $(EXEC_TARGS); do
$(SWENGENV)/puttarg $(PROD_ENG)/rt/lib $(TARG_DIR)/$$f Engineer $(NAME) "$(MESSAGE)"
done
for f in $(SRC_TARGS); do
$(SWENGENV)/puttarg $(PROD_ENG)/rt/include/wolfssl572 $$f Engineer $(NAME) "$(MESSAGE)"
done

for f in $(INCL_TARGS); do
dir=`dirname $$f | gres "wolfssl(.*)" "\1"`
if [ ! -d $(PROD_ENG)/rt/include/wolfssl572/wolfssl$$dir ] ; then
  mkdir $(PROD_ENG)/rt/include/wolfssl572/wolfssl$$dir
fi
$(SWENGENV)/puttarg $(PROD_ENG)/rt/include/wolfssl572/wolfssl$$dir ../../$$f Engineer $(NAME) "$(MESSAGE)"
done
]

"$(PROD_ENG)/rt/include/wolfssl572/wolfssl" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/openssl" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfcrypt/port/af_alg" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/aria" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/arm" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/atmel" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/autosar" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/caam" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/cavium" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/cypress" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/devcrypto" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/espressif" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/intel" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/iotsafe" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/kcapi" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/liboqs" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/maxim" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/nxp" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/pic32" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/psa" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/Renesas" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/riscv" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/silabs" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/st" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/ti" \
"$(PROD_ENG)/rt/include/wolfssl572/wolfssl/wolfcrypt/port/xilinx" \
"$(PROD_ENG)/rt/lib":
	$(MKSBIN)/mkdir -p $@

# Build project binaries, project help files, and sub-project binaries.
#
# NOTES:
#     1.  To ensure that the correct environment is present when invoking a MS
#         Developer Studio makefile, the rule initializes the required
#         environment variables in a sub-shell before invoking the makefile.
#
#     2.  Path vectors are converted to Microsoft-style pathname slashes
#         via 'redmond.ksh' before passing them as environment variables to 
#         Microsoft tools.

SOLUTIONFILE = wolfssl-lib.sln
.INCLUDE: $(SWENGENV)/vs2019.wnt

$(EXEC_TARGS) .PROLOG: rt_tree
[@
rm -f msbuild.log
msbuild $(SOLUTIONFILE) /t:Rebuild /p:Configuration=$(TARG_TYPE) /fileLogger
ec=$$?
if [ $$ec -ne 0 ]; then
  echo Failed to build $(@)
else
  echo Success!
fi
exit $$ec
]

