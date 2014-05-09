#
#  ======== cyassl.mak ========
#

# USER OPTIONAL STEP: These variables are set when building cyassl
# through the tirtos.mak
# Set up dependencies
XDC_INSTALL_DIR ?= C:/ti/xdctools_3_24_02_30
SYSBIOS_INSTALL_DIR ?= C:/ti/bios_6_34_01_14
NDK_INSTALL_DIR ?= C:/ti/ndk_2_24_00_02
TIRTOS_INSTALLATION_DIR ?= C:/ti/tirtos_tivac_2_00_00_22
TivaWareDir ?= C:/ti/tivaware
CYASSL_INSTALL_DIR ?= C:/cyassl/cyassl-2.9.4

#
# Set location of various cgtools
# These variables can be set here or on the command line. These
# variables are set when building cyassl through tirtos.mak
# USER OPTIONAL STEP: user can define below paths to compilers
ti.targets.arm.elf.M4F ?=

gnu.targets.arm.M4F ?=

iar.targets.arm.M4F ?=

#
# Set XDCARGS to some of the variables above.  XDCARGS are passed
# to the XDC build engine... which will load cyassl.bld... which will
# extract these variables and use them to determine what to build and which
# toolchains to use.
#
# Note that not all of these variables need to be set to something valid.
# Unfortunately, since these vars are unconditionally assigned, your build line
# will be longer and more noisy than necessary.
#
# Some background is here:
#     http://rtsc.eclipse.org/docs-tip/Command_-_xdc#Environment_Variables
#
XDCARGS= \
    ti.targets.arm.elf.M4F=\"$(ti.targets.arm.elf.M4F)\" \
    gnu.targets.arm.M4F=\"$(gnu.targets.arm.M4F)\" \
    iar.targets.arm.M4F=\"$(iar.targets.arm.M4F)\" \
    TivaWareDir=\"$(TivaWareDir)\" 

#
# Set XDCPATH to contain necessary repositories.
#
XDCPATH = $(SYSBIOS_INSTALL_DIR)/packages;$(NDK_INSTALL_DIR)/packages;$(CYASSL_INSTALL_DIR);$(TIRTOS_INSTALLATION_DIR)/packages;$(TivaWareDir);
export XDCPATH

#
# Set XDCOPTIONS.  Use -v for a verbose build.
#
#XDCOPTIONS=v
export XDCOPTIONS

#
# Set XDC executable command
# Note that XDCBUILDCFG points to the cyassl.bld file which uses
# the arguments specified by XDCARGS
#
XDC = $(XDC_INSTALL_DIR)/xdc XDCARGS="$(XDCARGS)" XDCBUILDCFG=./cyassl.bld

######################################################
## Shouldnt have to modify anything below this line ##
######################################################

all:
	@ echo building cyassl packages ...
	@ $(XDC) -Pr ./packages

clean:
	@ echo cleaning cyassl packages ...
	@ $(XDC) clean -Pr ./packages
