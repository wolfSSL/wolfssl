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
OUTPUT_SUFFIX=a
DEBUGGABLE_SUFFIX=
FINAL_IMAGE=dist/${CND_CONF}/${IMAGE_TYPE}/zlib.X.${OUTPUT_SUFFIX}
else
IMAGE_TYPE=production
OUTPUT_SUFFIX=a
DEBUGGABLE_SUFFIX=
FINAL_IMAGE=dist/${CND_CONF}/${IMAGE_TYPE}/zlib.X.${OUTPUT_SUFFIX}
endif

# Object Directory
OBJECTDIR=build/${CND_CONF}/${IMAGE_TYPE}

# Distribution Directory
DISTDIR=dist/${CND_CONF}/${IMAGE_TYPE}

# Source Files Quoted if spaced
SOURCEFILES_QUOTED_IF_SPACED=../../zlib-1.2.7/adler32.c ../../zlib-1.2.7/compress.c ../../zlib-1.2.7/crc32.c ../../zlib-1.2.7/deflate.c ../../zlib-1.2.7/gzclose.c ../../zlib-1.2.7/gzlib.c ../../zlib-1.2.7/gzread.c ../../zlib-1.2.7/gzwrite.c ../../zlib-1.2.7/infback.c ../../zlib-1.2.7/inffast.c ../../zlib-1.2.7/inflate.c ../../zlib-1.2.7/inftrees.c ../../zlib-1.2.7/trees.c ../../zlib-1.2.7/uncompr.c ../../zlib-1.2.7/zutil.c

# Object Files Quoted if spaced
OBJECTFILES_QUOTED_IF_SPACED=${OBJECTDIR}/_ext/608321700/adler32.o ${OBJECTDIR}/_ext/608321700/compress.o ${OBJECTDIR}/_ext/608321700/crc32.o ${OBJECTDIR}/_ext/608321700/deflate.o ${OBJECTDIR}/_ext/608321700/gzclose.o ${OBJECTDIR}/_ext/608321700/gzlib.o ${OBJECTDIR}/_ext/608321700/gzread.o ${OBJECTDIR}/_ext/608321700/gzwrite.o ${OBJECTDIR}/_ext/608321700/infback.o ${OBJECTDIR}/_ext/608321700/inffast.o ${OBJECTDIR}/_ext/608321700/inflate.o ${OBJECTDIR}/_ext/608321700/inftrees.o ${OBJECTDIR}/_ext/608321700/trees.o ${OBJECTDIR}/_ext/608321700/uncompr.o ${OBJECTDIR}/_ext/608321700/zutil.o
POSSIBLE_DEPFILES=${OBJECTDIR}/_ext/608321700/adler32.o.d ${OBJECTDIR}/_ext/608321700/compress.o.d ${OBJECTDIR}/_ext/608321700/crc32.o.d ${OBJECTDIR}/_ext/608321700/deflate.o.d ${OBJECTDIR}/_ext/608321700/gzclose.o.d ${OBJECTDIR}/_ext/608321700/gzlib.o.d ${OBJECTDIR}/_ext/608321700/gzread.o.d ${OBJECTDIR}/_ext/608321700/gzwrite.o.d ${OBJECTDIR}/_ext/608321700/infback.o.d ${OBJECTDIR}/_ext/608321700/inffast.o.d ${OBJECTDIR}/_ext/608321700/inflate.o.d ${OBJECTDIR}/_ext/608321700/inftrees.o.d ${OBJECTDIR}/_ext/608321700/trees.o.d ${OBJECTDIR}/_ext/608321700/uncompr.o.d ${OBJECTDIR}/_ext/608321700/zutil.o.d

# Object Files
OBJECTFILES=${OBJECTDIR}/_ext/608321700/adler32.o ${OBJECTDIR}/_ext/608321700/compress.o ${OBJECTDIR}/_ext/608321700/crc32.o ${OBJECTDIR}/_ext/608321700/deflate.o ${OBJECTDIR}/_ext/608321700/gzclose.o ${OBJECTDIR}/_ext/608321700/gzlib.o ${OBJECTDIR}/_ext/608321700/gzread.o ${OBJECTDIR}/_ext/608321700/gzwrite.o ${OBJECTDIR}/_ext/608321700/infback.o ${OBJECTDIR}/_ext/608321700/inffast.o ${OBJECTDIR}/_ext/608321700/inflate.o ${OBJECTDIR}/_ext/608321700/inftrees.o ${OBJECTDIR}/_ext/608321700/trees.o ${OBJECTDIR}/_ext/608321700/uncompr.o ${OBJECTDIR}/_ext/608321700/zutil.o

# Source Files
SOURCEFILES=../../zlib-1.2.7/adler32.c ../../zlib-1.2.7/compress.c ../../zlib-1.2.7/crc32.c ../../zlib-1.2.7/deflate.c ../../zlib-1.2.7/gzclose.c ../../zlib-1.2.7/gzlib.c ../../zlib-1.2.7/gzread.c ../../zlib-1.2.7/gzwrite.c ../../zlib-1.2.7/infback.c ../../zlib-1.2.7/inffast.c ../../zlib-1.2.7/inflate.c ../../zlib-1.2.7/inftrees.c ../../zlib-1.2.7/trees.c ../../zlib-1.2.7/uncompr.c ../../zlib-1.2.7/zutil.c


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
	${MAKE} ${MAKE_OPTIONS} -f nbproject/Makefile-default.mk dist/${CND_CONF}/${IMAGE_TYPE}/zlib.X.${OUTPUT_SUFFIX}

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
${OBJECTDIR}/_ext/608321700/adler32.o: ../../zlib-1.2.7/adler32.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/adler32.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/adler32.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/adler32.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/adler32.o.d" -o ${OBJECTDIR}/_ext/608321700/adler32.o ../../zlib-1.2.7/adler32.c   
	
${OBJECTDIR}/_ext/608321700/compress.o: ../../zlib-1.2.7/compress.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/compress.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/compress.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/compress.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/compress.o.d" -o ${OBJECTDIR}/_ext/608321700/compress.o ../../zlib-1.2.7/compress.c   
	
${OBJECTDIR}/_ext/608321700/crc32.o: ../../zlib-1.2.7/crc32.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/crc32.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/crc32.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/crc32.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/crc32.o.d" -o ${OBJECTDIR}/_ext/608321700/crc32.o ../../zlib-1.2.7/crc32.c   
	
${OBJECTDIR}/_ext/608321700/deflate.o: ../../zlib-1.2.7/deflate.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/deflate.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/deflate.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/deflate.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/deflate.o.d" -o ${OBJECTDIR}/_ext/608321700/deflate.o ../../zlib-1.2.7/deflate.c   
	
${OBJECTDIR}/_ext/608321700/gzclose.o: ../../zlib-1.2.7/gzclose.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/gzclose.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/gzclose.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/gzclose.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/gzclose.o.d" -o ${OBJECTDIR}/_ext/608321700/gzclose.o ../../zlib-1.2.7/gzclose.c   
	
${OBJECTDIR}/_ext/608321700/gzlib.o: ../../zlib-1.2.7/gzlib.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/gzlib.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/gzlib.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/gzlib.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/gzlib.o.d" -o ${OBJECTDIR}/_ext/608321700/gzlib.o ../../zlib-1.2.7/gzlib.c   
	
${OBJECTDIR}/_ext/608321700/gzread.o: ../../zlib-1.2.7/gzread.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/gzread.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/gzread.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/gzread.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/gzread.o.d" -o ${OBJECTDIR}/_ext/608321700/gzread.o ../../zlib-1.2.7/gzread.c   
	
${OBJECTDIR}/_ext/608321700/gzwrite.o: ../../zlib-1.2.7/gzwrite.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/gzwrite.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/gzwrite.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/gzwrite.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/gzwrite.o.d" -o ${OBJECTDIR}/_ext/608321700/gzwrite.o ../../zlib-1.2.7/gzwrite.c   
	
${OBJECTDIR}/_ext/608321700/infback.o: ../../zlib-1.2.7/infback.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/infback.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/infback.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/infback.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/infback.o.d" -o ${OBJECTDIR}/_ext/608321700/infback.o ../../zlib-1.2.7/infback.c   
	
${OBJECTDIR}/_ext/608321700/inffast.o: ../../zlib-1.2.7/inffast.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/inffast.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/inffast.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/inffast.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/inffast.o.d" -o ${OBJECTDIR}/_ext/608321700/inffast.o ../../zlib-1.2.7/inffast.c   
	
${OBJECTDIR}/_ext/608321700/inflate.o: ../../zlib-1.2.7/inflate.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/inflate.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/inflate.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/inflate.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/inflate.o.d" -o ${OBJECTDIR}/_ext/608321700/inflate.o ../../zlib-1.2.7/inflate.c   
	
${OBJECTDIR}/_ext/608321700/inftrees.o: ../../zlib-1.2.7/inftrees.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/inftrees.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/inftrees.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/inftrees.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/inftrees.o.d" -o ${OBJECTDIR}/_ext/608321700/inftrees.o ../../zlib-1.2.7/inftrees.c   
	
${OBJECTDIR}/_ext/608321700/trees.o: ../../zlib-1.2.7/trees.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/trees.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/trees.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/trees.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/trees.o.d" -o ${OBJECTDIR}/_ext/608321700/trees.o ../../zlib-1.2.7/trees.c   
	
${OBJECTDIR}/_ext/608321700/uncompr.o: ../../zlib-1.2.7/uncompr.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/uncompr.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/uncompr.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/uncompr.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/uncompr.o.d" -o ${OBJECTDIR}/_ext/608321700/uncompr.o ../../zlib-1.2.7/uncompr.c   
	
${OBJECTDIR}/_ext/608321700/zutil.o: ../../zlib-1.2.7/zutil.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/zutil.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/zutil.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/zutil.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/zutil.o.d" -o ${OBJECTDIR}/_ext/608321700/zutil.o ../../zlib-1.2.7/zutil.c   
	
else
${OBJECTDIR}/_ext/608321700/adler32.o: ../../zlib-1.2.7/adler32.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/adler32.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/adler32.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/adler32.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -g -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/adler32.o.d" -o ${OBJECTDIR}/_ext/608321700/adler32.o ../../zlib-1.2.7/adler32.c   
	
${OBJECTDIR}/_ext/608321700/compress.o: ../../zlib-1.2.7/compress.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/compress.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/compress.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/compress.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -g -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/compress.o.d" -o ${OBJECTDIR}/_ext/608321700/compress.o ../../zlib-1.2.7/compress.c   
	
${OBJECTDIR}/_ext/608321700/crc32.o: ../../zlib-1.2.7/crc32.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/crc32.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/crc32.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/crc32.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -g -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/crc32.o.d" -o ${OBJECTDIR}/_ext/608321700/crc32.o ../../zlib-1.2.7/crc32.c   
	
${OBJECTDIR}/_ext/608321700/deflate.o: ../../zlib-1.2.7/deflate.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/deflate.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/deflate.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/deflate.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -g -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/deflate.o.d" -o ${OBJECTDIR}/_ext/608321700/deflate.o ../../zlib-1.2.7/deflate.c   
	
${OBJECTDIR}/_ext/608321700/gzclose.o: ../../zlib-1.2.7/gzclose.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/gzclose.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/gzclose.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/gzclose.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -g -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/gzclose.o.d" -o ${OBJECTDIR}/_ext/608321700/gzclose.o ../../zlib-1.2.7/gzclose.c   
	
${OBJECTDIR}/_ext/608321700/gzlib.o: ../../zlib-1.2.7/gzlib.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/gzlib.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/gzlib.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/gzlib.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -g -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/gzlib.o.d" -o ${OBJECTDIR}/_ext/608321700/gzlib.o ../../zlib-1.2.7/gzlib.c   
	
${OBJECTDIR}/_ext/608321700/gzread.o: ../../zlib-1.2.7/gzread.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/gzread.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/gzread.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/gzread.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -g -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/gzread.o.d" -o ${OBJECTDIR}/_ext/608321700/gzread.o ../../zlib-1.2.7/gzread.c   
	
${OBJECTDIR}/_ext/608321700/gzwrite.o: ../../zlib-1.2.7/gzwrite.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/gzwrite.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/gzwrite.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/gzwrite.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -g -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/gzwrite.o.d" -o ${OBJECTDIR}/_ext/608321700/gzwrite.o ../../zlib-1.2.7/gzwrite.c   
	
${OBJECTDIR}/_ext/608321700/infback.o: ../../zlib-1.2.7/infback.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/infback.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/infback.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/infback.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -g -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/infback.o.d" -o ${OBJECTDIR}/_ext/608321700/infback.o ../../zlib-1.2.7/infback.c   
	
${OBJECTDIR}/_ext/608321700/inffast.o: ../../zlib-1.2.7/inffast.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/inffast.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/inffast.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/inffast.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -g -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/inffast.o.d" -o ${OBJECTDIR}/_ext/608321700/inffast.o ../../zlib-1.2.7/inffast.c   
	
${OBJECTDIR}/_ext/608321700/inflate.o: ../../zlib-1.2.7/inflate.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/inflate.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/inflate.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/inflate.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -g -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/inflate.o.d" -o ${OBJECTDIR}/_ext/608321700/inflate.o ../../zlib-1.2.7/inflate.c   
	
${OBJECTDIR}/_ext/608321700/inftrees.o: ../../zlib-1.2.7/inftrees.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/inftrees.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/inftrees.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/inftrees.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -g -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/inftrees.o.d" -o ${OBJECTDIR}/_ext/608321700/inftrees.o ../../zlib-1.2.7/inftrees.c   
	
${OBJECTDIR}/_ext/608321700/trees.o: ../../zlib-1.2.7/trees.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/trees.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/trees.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/trees.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -g -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/trees.o.d" -o ${OBJECTDIR}/_ext/608321700/trees.o ../../zlib-1.2.7/trees.c   
	
${OBJECTDIR}/_ext/608321700/uncompr.o: ../../zlib-1.2.7/uncompr.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/uncompr.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/uncompr.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/uncompr.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -g -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/uncompr.o.d" -o ${OBJECTDIR}/_ext/608321700/uncompr.o ../../zlib-1.2.7/uncompr.c   
	
${OBJECTDIR}/_ext/608321700/zutil.o: ../../zlib-1.2.7/zutil.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} ${OBJECTDIR}/_ext/608321700 
	@${RM} ${OBJECTDIR}/_ext/608321700/zutil.o.d 
	@${RM} ${OBJECTDIR}/_ext/608321700/zutil.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/608321700/zutil.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -g -x c -c -mprocessor=$(MP_PROCESSOR_OPTION) -Os -DHAVE_HIDDEN -DMAX_MEM_LEVEL=1 -DMAX_WBITS=11 -DCYASSL_MICROCHIP_PIC32MZ -I"../../zlib-1.2.7" -MMD -MF "${OBJECTDIR}/_ext/608321700/zutil.o.d" -o ${OBJECTDIR}/_ext/608321700/zutil.o ../../zlib-1.2.7/zutil.c   
	
endif

# ------------------------------------------------------------------------------------
# Rules for buildStep: compileCPP
ifeq ($(TYPE_IMAGE), DEBUG_RUN)
else
endif

# ------------------------------------------------------------------------------------
# Rules for buildStep: archive
ifeq ($(TYPE_IMAGE), DEBUG_RUN)
dist/${CND_CONF}/${IMAGE_TYPE}/zlib.X.${OUTPUT_SUFFIX}: ${OBJECTFILES}  nbproject/Makefile-${CND_CONF}.mk    
	@${MKDIR} dist/${CND_CONF}/${IMAGE_TYPE} 
	${MP_AR} $(MP_EXTRA_AR_PRE) r dist/${CND_CONF}/${IMAGE_TYPE}/zlib.X.${OUTPUT_SUFFIX} ${OBJECTFILES_QUOTED_IF_SPACED}    
else
dist/${CND_CONF}/${IMAGE_TYPE}/zlib.X.${OUTPUT_SUFFIX}: ${OBJECTFILES}  nbproject/Makefile-${CND_CONF}.mk   
	@${MKDIR} dist/${CND_CONF}/${IMAGE_TYPE} 
	${MP_AR} $(MP_EXTRA_AR_PRE) r dist/${CND_CONF}/${IMAGE_TYPE}/zlib.X.${OUTPUT_SUFFIX} ${OBJECTFILES_QUOTED_IF_SPACED}    
endif


# Subprojects
.build-subprojects:


# Subprojects
.clean-subprojects:

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
