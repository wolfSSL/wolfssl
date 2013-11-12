#
# Generated Makefile - do not edit!
#
# Edit the Makefile in the project folder instead (../Makefile). Each target
# has a -pre and a -post target defined where you can add customized code.
#
# This makefile implements configuration specific macros and targets.


# Include project Makefile
ifeq "${IGNORE_LOCAL}" "TRUE"
# do not include local makefile. User is passing all local related variables already
else
include Makefile
# Include makefile containing local settings
ifeq "$(wildcard nbproject/Makefile-local-default.mk)" "nbproject/Makefile-local-default.mk"
include nbproject/Makefile-local-default.mk
endif
endif

# Environment
MKDIR=gnumkdir -p
RM=rm -f 
MV=mv 
CP=cp 

# Macros
CND_CONF=default
ifeq ($(TYPE_IMAGE), DEBUG_RUN)
IMAGE_TYPE=debug
OUTPUT_SUFFIX=elf
DEBUGGABLE_SUFFIX=elf
FINAL_IMAGE=dist/${CND_CONF}/${IMAGE_TYPE}/ctaocrypt_test.X.${IMAGE_TYPE}.${OUTPUT_SUFFIX}
else
IMAGE_TYPE=production
OUTPUT_SUFFIX=hex
DEBUGGABLE_SUFFIX=elf
FINAL_IMAGE=dist/${CND_CONF}/${IMAGE_TYPE}/ctaocrypt_test.X.${IMAGE_TYPE}.${OUTPUT_SUFFIX}
endif

# Object Directory
OBJECTDIR=build/${CND_CONF}/${IMAGE_TYPE}

# Distribution Directory
DISTDIR=dist/${CND_CONF}/${IMAGE_TYPE}

# Source Files Quoted if spaced
SOURCEFILES_QUOTED_IF_SPACED=../../ctaocrypt/test/test.c ../../mplabx/test_main.c

# Object Files Quoted if spaced
OBJECTFILES_QUOTED_IF_SPACED=${OBJECTDIR}/_ext/1679622190/test.o ${OBJECTDIR}/_ext/1042050482/test_main.o
POSSIBLE_DEPFILES=${OBJECTDIR}/_ext/1679622190/test.o.d ${OBJECTDIR}/_ext/1042050482/test_main.o.d

# Object Files
OBJECTFILES=${OBJECTDIR}/_ext/1679622190/test.o ${OBJECTDIR}/_ext/1042050482/test_main.o

# Source Files
SOURCEFILES=../../ctaocrypt/test/test.c ../../mplabx/test_main.c


CFLAGS=
ASFLAGS=
LDLIBSOPTIONS=

############# Tool locations ##########################################
# If you copy a project from one host to another, the path where the  #
# compiler is installed may be different.                             #
# If you open this project with MPLAB X in the new host, this         #
# makefile will be regenerated and the paths will be corrected.       #
#######################################################################
# fixDeps replaces a bunch of sed/cat/printf statements that slow down the build
FIXDEPS=fixDeps

.build-conf:  ${BUILD_SUBPROJECTS}
	${MAKE} ${MAKE_OPTIONS} -f nbproject/Makefile-default.mk dist/${CND_CONF}/${IMAGE_TYPE}/ctaocrypt_test.X.${IMAGE_TYPE}.${OUTPUT_SUFFIX}

MP_PROCESSOR_OPTION=32MZ2048ECM144
MP_LINKER_FILE_OPTION=
# ------------------------------------------------------------------------------------
# Rules for buildStep: assemble
ifeq ($(TYPE_IMAGE), DEBUG_RUN)
else
endif

# ------------------------------------------------------------------------------------
# Rules for buildStep: assembleWithPreprocess
ifeq ($(TYPE_IMAGE), DEBUG_RUN)
else
endif

# ------------------------------------------------------------------------------------
# Rules for buildStep: compile
ifeq ($(TYPE_IMAGE), DEBUG_RUN)
${OBJECTDIR}/_ext/1679622190/test.o: ../../ctaocrypt/test/test.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/1679622190 
	@${RM} ${OBJECTDIR}/_ext/1679622190/test.o.d 
	@${RM} ${OBJECTDIR}/_ext/1679622190/test.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/1679622190/test.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DNO_MAIN_DRIVER -DUSE_CERT_BUFFERS_1024 -DCYASSL_SHA384 -DCYASSL_SHA512 -DHAVE_ECC -DHAVE_LIBZ -DHAVE_MCAPI -DCYASSL_MICROCHIP_PIC32MZ -I"../../" -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/1679622190/test.o.d" -o ${OBJECTDIR}/_ext/1679622190/test.o ../../ctaocrypt/test/test.c   
	
${OBJECTDIR}/_ext/1042050482/test_main.o: ../../mplabx/test_main.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/1042050482 
	@${RM} ${OBJECTDIR}/_ext/1042050482/test_main.o.d 
	@${RM} ${OBJECTDIR}/_ext/1042050482/test_main.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/1042050482/test_main.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DNO_MAIN_DRIVER -DUSE_CERT_BUFFERS_1024 -DCYASSL_SHA384 -DCYASSL_SHA512 -DHAVE_ECC -DHAVE_LIBZ -DHAVE_MCAPI -DCYASSL_MICROCHIP_PIC32MZ -I"../../" -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/1042050482/test_main.o.d" -o ${OBJECTDIR}/_ext/1042050482/test_main.o ../../mplabx/test_main.c   
	
else
${OBJECTDIR}/_ext/1679622190/test.o: ../../ctaocrypt/test/test.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/1679622190 
	@${RM} ${OBJECTDIR}/_ext/1679622190/test.o.d 
	@${RM} ${OBJECTDIR}/_ext/1679622190/test.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/1679622190/test.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DNO_MAIN_DRIVER -DUSE_CERT_BUFFERS_1024 -DCYASSL_SHA384 -DCYASSL_SHA512 -DHAVE_ECC -DHAVE_LIBZ -DHAVE_MCAPI -DCYASSL_MICROCHIP_PIC32MZ -I"../../" -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/1679622190/test.o.d" -o ${OBJECTDIR}/_ext/1679622190/test.o ../../ctaocrypt/test/test.c   
	
${OBJECTDIR}/_ext/1042050482/test_main.o: ../../mplabx/test_main.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/1042050482 
	@${RM} ${OBJECTDIR}/_ext/1042050482/test_main.o.d 
	@${RM} ${OBJECTDIR}/_ext/1042050482/test_main.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/1042050482/test_main.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DNO_MAIN_DRIVER -DUSE_CERT_BUFFERS_1024 -DCYASSL_SHA384 -DCYASSL_SHA512 -DHAVE_ECC -DHAVE_LIBZ -DHAVE_MCAPI -DCYASSL_MICROCHIP_PIC32MZ -I"../../" -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/1042050482/test_main.o.d" -o ${OBJECTDIR}/_ext/1042050482/test_main.o ../../mplabx/test_main.c   
	
endif

# ------------------------------------------------------------------------------------
# Rules for buildStep: compileCPP
ifeq ($(TYPE_IMAGE), DEBUG_RUN)
else
endif

# ------------------------------------------------------------------------------------
# Rules for buildStep: link
ifeq ($(TYPE_IMAGE), DEBUG_RUN)
dist/${CND_CONF}/${IMAGE_TYPE}/ctaocrypt_test.X.${IMAGE_TYPE}.${OUTPUT_SUFFIX}: ${OBJECTFILES}  nbproject/Makefile-${CND_CONF}.mk  ../cyassl.X/dist/default/debug/cyassl.X.a ../zlib.X/dist/default/debug/zlib.X.a  
	@${MKDIR} dist/${CND_CONF}/${IMAGE_TYPE} 
	${MP_CC} $(MP_EXTRA_LD_PRE)  -mdebugger -D__MPLAB_DEBUGGER_PK3=1 -mprocessor=$(MP_PROCESSOR_OPTION) -Os -o dist/${CND_CONF}/${IMAGE_TYPE}/ctaocrypt_test.X.${IMAGE_TYPE}.${OUTPUT_SUFFIX} ${OBJECTFILES_QUOTED_IF_SPACED}    ..\cyassl.X\dist\default\debug\cyassl.X.a ..\zlib.X\dist\default\debug\zlib.X.a       -mreserve=data@0x0:0x27F   -Wl,--defsym=__MPLAB_BUILD=1$(MP_EXTRA_LD_POST)$(MP_LINKER_FILE_OPTION),--defsym=__MPLAB_DEBUG=1,--defsym=__DEBUG=1,--defsym=__MPLAB_DEBUGGER_PK3=1,--defsym=_min_heap_size=32768,--defsym=_min_stack_size=1024,--gc-sections
	
else
dist/${CND_CONF}/${IMAGE_TYPE}/ctaocrypt_test.X.${IMAGE_TYPE}.${OUTPUT_SUFFIX}: ${OBJECTFILES}  nbproject/Makefile-${CND_CONF}.mk  ../cyassl.X/dist/default/production/cyassl.X.a ../zlib.X/dist/default/production/zlib.X.a 
	@${MKDIR} dist/${CND_CONF}/${IMAGE_TYPE} 
	${MP_CC} $(MP_EXTRA_LD_PRE)  -mprocessor=$(MP_PROCESSOR_OPTION) -Os -o dist/${CND_CONF}/${IMAGE_TYPE}/ctaocrypt_test.X.${IMAGE_TYPE}.${DEBUGGABLE_SUFFIX} ${OBJECTFILES_QUOTED_IF_SPACED}    ..\cyassl.X\dist\default\production\cyassl.X.a ..\zlib.X\dist\default\production\zlib.X.a      -Wl,--defsym=__MPLAB_BUILD=1$(MP_EXTRA_LD_POST)$(MP_LINKER_FILE_OPTION),--defsym=_min_heap_size=32768,--defsym=_min_stack_size=1024,--gc-sections
	${MP_CC_DIR}\\xc32-bin2hex dist/${CND_CONF}/${IMAGE_TYPE}/ctaocrypt_test.X.${IMAGE_TYPE}.${DEBUGGABLE_SUFFIX} 
endif


# Subprojects
.build-subprojects:
	cd /D ../cyassl.X && ${MAKE}  -f Makefile CONF=default
	cd /D ../zlib.X && ${MAKE}  -f Makefile CONF=default


# Subprojects
.clean-subprojects:
	cd /D ../cyassl.X && rm -rf "build/default" "dist/default"
	cd /D ../zlib.X && rm -rf "build/default" "dist/default"

# Clean Targets
.clean-conf: ${CLEAN_SUBPROJECTS}
	${RM} -r build/default
	${RM} -r dist/default

# Enable dependency checking
.dep.inc: .depcheck-impl

DEPFILES=$(shell mplabwildcard ${POSSIBLE_DEPFILES})
ifneq (${DEPFILES},)
include ${DEPFILES}
endif
