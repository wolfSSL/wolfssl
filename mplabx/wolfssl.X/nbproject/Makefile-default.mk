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
MKDIR=mkdir -p
RM=rm -f 
MV=mv 
CP=cp 

# Macros
CND_CONF=default
ifeq ($(TYPE_IMAGE), DEBUG_RUN)
IMAGE_TYPE=debug
OUTPUT_SUFFIX=a
DEBUGGABLE_SUFFIX=
FINAL_IMAGE=dist/${CND_CONF}/${IMAGE_TYPE}/wolfssl.X.${OUTPUT_SUFFIX}
else
IMAGE_TYPE=production
OUTPUT_SUFFIX=a
DEBUGGABLE_SUFFIX=
FINAL_IMAGE=dist/${CND_CONF}/${IMAGE_TYPE}/wolfssl.X.${OUTPUT_SUFFIX}
endif

# Object Directory
OBJECTDIR=build/${CND_CONF}/${IMAGE_TYPE}

# Distribution Directory
DISTDIR=dist/${CND_CONF}/${IMAGE_TYPE}

# Source Files Quoted if spaced
SOURCEFILES_QUOTED_IF_SPACED=../../wolfcrypt/src/aes.c ../../wolfcrypt/src/arc4.c ../../wolfcrypt/src/asm.c ../../wolfcrypt/src/asn.c ../../wolfcrypt/src/blake2b.c ../../wolfcrypt/src/camellia.c ../../wolfcrypt/src/chacha.c ../../wolfcrypt/src/coding.c ../../wolfcrypt/src/compress.c ../../wolfcrypt/src/des3.c ../../wolfcrypt/src/dh.c ../../wolfcrypt/src/dsa.c ../../wolfcrypt/src/ecc.c ../../wolfcrypt/src/ecc_fp.c ../../wolfcrypt/src/error.c ../../wolfcrypt/src/hc128.c ../../wolfcrypt/src/hmac.c ../../wolfcrypt/src/integer.c ../../wolfcrypt/src/logging.c ../../wolfcrypt/src/md2.c ../../wolfcrypt/src/md4.c ../../wolfcrypt/src/md5.c ../../wolfcrypt/src/memory.c ../../wolfcrypt/src/misc.c ../../wolfcrypt/src/pkcs7.c ../../wolfcrypt/src/poly1305.c ../../wolfcrypt/src/pwdbased.c ../../wolfcrypt/src/rabbit.c ../../wolfcrypt/src/random.c ../../wolfcrypt/src/ripemd.c ../../wolfcrypt/src/rsa.c ../../wolfcrypt/src/sha.c ../../wolfcrypt/src/sha256.c ../../wolfcrypt/src/sha512.c ../../wolfcrypt/src/tfm.c ../../wolfcrypt/src/wc_port.c ../../wolfcrypt/src/port/pic32/pic32mz-hash.c ../../src/crl.c ../../src/internal.c ../../src/io.c ../../src/keys.c ../../src/ocsp.c ../../src/sniffer.c ../../src/ssl.c ../../src/tls.c

# Object Files Quoted if spaced
OBJECTFILES_QUOTED_IF_SPACED=${OBJECTDIR}/_ext/181168623/aes.o ${OBJECTDIR}/_ext/181168623/arc4.o ${OBJECTDIR}/_ext/181168623/asm.o ${OBJECTDIR}/_ext/181168623/asn.o ${OBJECTDIR}/_ext/181168623/blake2b.o ${OBJECTDIR}/_ext/181168623/camellia.o ${OBJECTDIR}/_ext/181168623/chacha.o ${OBJECTDIR}/_ext/181168623/coding.o ${OBJECTDIR}/_ext/181168623/compress.o ${OBJECTDIR}/_ext/181168623/des3.o ${OBJECTDIR}/_ext/181168623/dh.o ${OBJECTDIR}/_ext/181168623/dsa.o ${OBJECTDIR}/_ext/181168623/ecc.o ${OBJECTDIR}/_ext/181168623/ecc_fp.o ${OBJECTDIR}/_ext/181168623/error.o ${OBJECTDIR}/_ext/181168623/hc128.o ${OBJECTDIR}/_ext/181168623/hmac.o ${OBJECTDIR}/_ext/181168623/integer.o ${OBJECTDIR}/_ext/181168623/logging.o ${OBJECTDIR}/_ext/181168623/md2.o ${OBJECTDIR}/_ext/181168623/md4.o ${OBJECTDIR}/_ext/181168623/md5.o ${OBJECTDIR}/_ext/181168623/memory.o ${OBJECTDIR}/_ext/181168623/misc.o ${OBJECTDIR}/_ext/181168623/pkcs7.o ${OBJECTDIR}/_ext/181168623/poly1305.o ${OBJECTDIR}/_ext/181168623/pwdbased.o ${OBJECTDIR}/_ext/181168623/rabbit.o ${OBJECTDIR}/_ext/181168623/random.o ${OBJECTDIR}/_ext/181168623/ripemd.o ${OBJECTDIR}/_ext/181168623/rsa.o ${OBJECTDIR}/_ext/181168623/sha.o ${OBJECTDIR}/_ext/181168623/sha256.o ${OBJECTDIR}/_ext/181168623/sha512.o ${OBJECTDIR}/_ext/181168623/tfm.o ${OBJECTDIR}/_ext/181168623/wc_port.o ${OBJECTDIR}/_ext/2020528871/pic32mz-hash.o ${OBJECTDIR}/_ext/1445274692/crl.o ${OBJECTDIR}/_ext/1445274692/internal.o ${OBJECTDIR}/_ext/1445274692/io.o ${OBJECTDIR}/_ext/1445274692/keys.o ${OBJECTDIR}/_ext/1445274692/ocsp.o ${OBJECTDIR}/_ext/1445274692/sniffer.o ${OBJECTDIR}/_ext/1445274692/ssl.o ${OBJECTDIR}/_ext/1445274692/tls.o
POSSIBLE_DEPFILES=${OBJECTDIR}/_ext/181168623/aes.o.d ${OBJECTDIR}/_ext/181168623/arc4.o.d ${OBJECTDIR}/_ext/181168623/asm.o.d ${OBJECTDIR}/_ext/181168623/asn.o.d ${OBJECTDIR}/_ext/181168623/blake2b.o.d ${OBJECTDIR}/_ext/181168623/camellia.o.d ${OBJECTDIR}/_ext/181168623/chacha.o.d ${OBJECTDIR}/_ext/181168623/coding.o.d ${OBJECTDIR}/_ext/181168623/compress.o.d ${OBJECTDIR}/_ext/181168623/des3.o.d ${OBJECTDIR}/_ext/181168623/dh.o.d ${OBJECTDIR}/_ext/181168623/dsa.o.d ${OBJECTDIR}/_ext/181168623/ecc.o.d ${OBJECTDIR}/_ext/181168623/ecc_fp.o.d ${OBJECTDIR}/_ext/181168623/error.o.d ${OBJECTDIR}/_ext/181168623/hc128.o.d ${OBJECTDIR}/_ext/181168623/hmac.o.d ${OBJECTDIR}/_ext/181168623/integer.o.d ${OBJECTDIR}/_ext/181168623/logging.o.d ${OBJECTDIR}/_ext/181168623/md2.o.d ${OBJECTDIR}/_ext/181168623/md4.o.d ${OBJECTDIR}/_ext/181168623/md5.o.d ${OBJECTDIR}/_ext/181168623/memory.o.d ${OBJECTDIR}/_ext/181168623/misc.o.d ${OBJECTDIR}/_ext/181168623/pkcs7.o.d ${OBJECTDIR}/_ext/181168623/poly1305.o.d ${OBJECTDIR}/_ext/181168623/pwdbased.o.d ${OBJECTDIR}/_ext/181168623/rabbit.o.d ${OBJECTDIR}/_ext/181168623/random.o.d ${OBJECTDIR}/_ext/181168623/ripemd.o.d ${OBJECTDIR}/_ext/181168623/rsa.o.d ${OBJECTDIR}/_ext/181168623/sha.o.d ${OBJECTDIR}/_ext/181168623/sha256.o.d ${OBJECTDIR}/_ext/181168623/sha512.o.d ${OBJECTDIR}/_ext/181168623/tfm.o.d ${OBJECTDIR}/_ext/181168623/wc_port.o.d ${OBJECTDIR}/_ext/2020528871/pic32mz-hash.o.d ${OBJECTDIR}/_ext/1445274692/crl.o.d ${OBJECTDIR}/_ext/1445274692/internal.o.d ${OBJECTDIR}/_ext/1445274692/io.o.d ${OBJECTDIR}/_ext/1445274692/keys.o.d ${OBJECTDIR}/_ext/1445274692/ocsp.o.d ${OBJECTDIR}/_ext/1445274692/sniffer.o.d ${OBJECTDIR}/_ext/1445274692/ssl.o.d ${OBJECTDIR}/_ext/1445274692/tls.o.d

# Object Files
OBJECTFILES=${OBJECTDIR}/_ext/181168623/aes.o ${OBJECTDIR}/_ext/181168623/arc4.o ${OBJECTDIR}/_ext/181168623/asm.o ${OBJECTDIR}/_ext/181168623/asn.o ${OBJECTDIR}/_ext/181168623/blake2b.o ${OBJECTDIR}/_ext/181168623/camellia.o ${OBJECTDIR}/_ext/181168623/chacha.o ${OBJECTDIR}/_ext/181168623/coding.o ${OBJECTDIR}/_ext/181168623/compress.o ${OBJECTDIR}/_ext/181168623/des3.o ${OBJECTDIR}/_ext/181168623/dh.o ${OBJECTDIR}/_ext/181168623/dsa.o ${OBJECTDIR}/_ext/181168623/ecc.o ${OBJECTDIR}/_ext/181168623/ecc_fp.o ${OBJECTDIR}/_ext/181168623/error.o ${OBJECTDIR}/_ext/181168623/hc128.o ${OBJECTDIR}/_ext/181168623/hmac.o ${OBJECTDIR}/_ext/181168623/integer.o ${OBJECTDIR}/_ext/181168623/logging.o ${OBJECTDIR}/_ext/181168623/md2.o ${OBJECTDIR}/_ext/181168623/md4.o ${OBJECTDIR}/_ext/181168623/md5.o ${OBJECTDIR}/_ext/181168623/memory.o ${OBJECTDIR}/_ext/181168623/misc.o ${OBJECTDIR}/_ext/181168623/pkcs7.o ${OBJECTDIR}/_ext/181168623/poly1305.o ${OBJECTDIR}/_ext/181168623/pwdbased.o ${OBJECTDIR}/_ext/181168623/rabbit.o ${OBJECTDIR}/_ext/181168623/random.o ${OBJECTDIR}/_ext/181168623/ripemd.o ${OBJECTDIR}/_ext/181168623/rsa.o ${OBJECTDIR}/_ext/181168623/sha.o ${OBJECTDIR}/_ext/181168623/sha256.o ${OBJECTDIR}/_ext/181168623/sha512.o ${OBJECTDIR}/_ext/181168623/tfm.o ${OBJECTDIR}/_ext/181168623/wc_port.o ${OBJECTDIR}/_ext/2020528871/pic32mz-hash.o ${OBJECTDIR}/_ext/1445274692/crl.o ${OBJECTDIR}/_ext/1445274692/internal.o ${OBJECTDIR}/_ext/1445274692/io.o ${OBJECTDIR}/_ext/1445274692/keys.o ${OBJECTDIR}/_ext/1445274692/ocsp.o ${OBJECTDIR}/_ext/1445274692/sniffer.o ${OBJECTDIR}/_ext/1445274692/ssl.o ${OBJECTDIR}/_ext/1445274692/tls.o

# Source Files
SOURCEFILES=../../wolfcrypt/src/aes.c ../../wolfcrypt/src/arc4.c ../../wolfcrypt/src/asm.c ../../wolfcrypt/src/asn.c ../../wolfcrypt/src/blake2b.c ../../wolfcrypt/src/camellia.c ../../wolfcrypt/src/chacha.c ../../wolfcrypt/src/coding.c ../../wolfcrypt/src/compress.c ../../wolfcrypt/src/des3.c ../../wolfcrypt/src/dh.c ../../wolfcrypt/src/dsa.c ../../wolfcrypt/src/ecc.c ../../wolfcrypt/src/ecc_fp.c ../../wolfcrypt/src/error.c ../../wolfcrypt/src/hc128.c ../../wolfcrypt/src/hmac.c ../../wolfcrypt/src/integer.c ../../wolfcrypt/src/logging.c ../../wolfcrypt/src/md2.c ../../wolfcrypt/src/md4.c ../../wolfcrypt/src/md5.c ../../wolfcrypt/src/memory.c ../../wolfcrypt/src/misc.c ../../wolfcrypt/src/pkcs7.c ../../wolfcrypt/src/poly1305.c ../../wolfcrypt/src/pwdbased.c ../../wolfcrypt/src/rabbit.c ../../wolfcrypt/src/random.c ../../wolfcrypt/src/ripemd.c ../../wolfcrypt/src/rsa.c ../../wolfcrypt/src/sha.c ../../wolfcrypt/src/sha256.c ../../wolfcrypt/src/sha512.c ../../wolfcrypt/src/tfm.c ../../wolfcrypt/src/wc_port.c ../../wolfcrypt/src/port/pic32/pic32mz-hash.c ../../src/crl.c ../../src/internal.c ../../src/io.c ../../src/keys.c ../../src/ocsp.c ../../src/sniffer.c ../../src/ssl.c ../../src/tls.c


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
ifneq ($(INFORMATION_MESSAGE), )
	@echo $(INFORMATION_MESSAGE)
endif
	${MAKE}  -f nbproject/Makefile-default.mk dist/${CND_CONF}/${IMAGE_TYPE}/wolfssl.X.${OUTPUT_SUFFIX}

MP_PROCESSOR_OPTION=32MX795F512L
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
${OBJECTDIR}/_ext/181168623/aes.o: ../../wolfcrypt/src/aes.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/aes.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/aes.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/aes.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/aes.o.d" -o ${OBJECTDIR}/_ext/181168623/aes.o ../../wolfcrypt/src/aes.c   
	
${OBJECTDIR}/_ext/181168623/arc4.o: ../../wolfcrypt/src/arc4.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/arc4.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/arc4.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/arc4.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/arc4.o.d" -o ${OBJECTDIR}/_ext/181168623/arc4.o ../../wolfcrypt/src/arc4.c   
	
${OBJECTDIR}/_ext/181168623/asm.o: ../../wolfcrypt/src/asm.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/asm.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/asm.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/asm.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/asm.o.d" -o ${OBJECTDIR}/_ext/181168623/asm.o ../../wolfcrypt/src/asm.c   
	
${OBJECTDIR}/_ext/181168623/asn.o: ../../wolfcrypt/src/asn.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/asn.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/asn.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/asn.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/asn.o.d" -o ${OBJECTDIR}/_ext/181168623/asn.o ../../wolfcrypt/src/asn.c   
	
${OBJECTDIR}/_ext/181168623/blake2b.o: ../../wolfcrypt/src/blake2b.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/blake2b.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/blake2b.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/blake2b.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/blake2b.o.d" -o ${OBJECTDIR}/_ext/181168623/blake2b.o ../../wolfcrypt/src/blake2b.c   
	
${OBJECTDIR}/_ext/181168623/camellia.o: ../../wolfcrypt/src/camellia.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/camellia.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/camellia.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/camellia.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/camellia.o.d" -o ${OBJECTDIR}/_ext/181168623/camellia.o ../../wolfcrypt/src/camellia.c   
	
${OBJECTDIR}/_ext/181168623/chacha.o: ../../wolfcrypt/src/chacha.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/chacha.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/chacha.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/chacha.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/chacha.o.d" -o ${OBJECTDIR}/_ext/181168623/chacha.o ../../wolfcrypt/src/chacha.c   
	
${OBJECTDIR}/_ext/181168623/coding.o: ../../wolfcrypt/src/coding.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/coding.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/coding.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/coding.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/coding.o.d" -o ${OBJECTDIR}/_ext/181168623/coding.o ../../wolfcrypt/src/coding.c   
	
${OBJECTDIR}/_ext/181168623/compress.o: ../../wolfcrypt/src/compress.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/compress.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/compress.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/compress.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/compress.o.d" -o ${OBJECTDIR}/_ext/181168623/compress.o ../../wolfcrypt/src/compress.c   
	
${OBJECTDIR}/_ext/181168623/des3.o: ../../wolfcrypt/src/des3.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/des3.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/des3.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/des3.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/des3.o.d" -o ${OBJECTDIR}/_ext/181168623/des3.o ../../wolfcrypt/src/des3.c   
	
${OBJECTDIR}/_ext/181168623/dh.o: ../../wolfcrypt/src/dh.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/dh.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/dh.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/dh.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/dh.o.d" -o ${OBJECTDIR}/_ext/181168623/dh.o ../../wolfcrypt/src/dh.c   
	
${OBJECTDIR}/_ext/181168623/dsa.o: ../../wolfcrypt/src/dsa.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/dsa.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/dsa.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/dsa.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/dsa.o.d" -o ${OBJECTDIR}/_ext/181168623/dsa.o ../../wolfcrypt/src/dsa.c   
	
${OBJECTDIR}/_ext/181168623/ecc.o: ../../wolfcrypt/src/ecc.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/ecc.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/ecc.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/ecc.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/ecc.o.d" -o ${OBJECTDIR}/_ext/181168623/ecc.o ../../wolfcrypt/src/ecc.c   
	
${OBJECTDIR}/_ext/181168623/ecc_fp.o: ../../wolfcrypt/src/ecc_fp.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/ecc_fp.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/ecc_fp.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/ecc_fp.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/ecc_fp.o.d" -o ${OBJECTDIR}/_ext/181168623/ecc_fp.o ../../wolfcrypt/src/ecc_fp.c   
	
${OBJECTDIR}/_ext/181168623/error.o: ../../wolfcrypt/src/error.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/error.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/error.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/error.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/error.o.d" -o ${OBJECTDIR}/_ext/181168623/error.o ../../wolfcrypt/src/error.c   
	
${OBJECTDIR}/_ext/181168623/hc128.o: ../../wolfcrypt/src/hc128.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/hc128.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/hc128.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/hc128.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/hc128.o.d" -o ${OBJECTDIR}/_ext/181168623/hc128.o ../../wolfcrypt/src/hc128.c   
	
${OBJECTDIR}/_ext/181168623/hmac.o: ../../wolfcrypt/src/hmac.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/hmac.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/hmac.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/hmac.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/hmac.o.d" -o ${OBJECTDIR}/_ext/181168623/hmac.o ../../wolfcrypt/src/hmac.c   
	
${OBJECTDIR}/_ext/181168623/integer.o: ../../wolfcrypt/src/integer.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/integer.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/integer.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/integer.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/integer.o.d" -o ${OBJECTDIR}/_ext/181168623/integer.o ../../wolfcrypt/src/integer.c   
	
${OBJECTDIR}/_ext/181168623/logging.o: ../../wolfcrypt/src/logging.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/logging.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/logging.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/logging.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/logging.o.d" -o ${OBJECTDIR}/_ext/181168623/logging.o ../../wolfcrypt/src/logging.c   
	
${OBJECTDIR}/_ext/181168623/md2.o: ../../wolfcrypt/src/md2.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/md2.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/md2.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/md2.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/md2.o.d" -o ${OBJECTDIR}/_ext/181168623/md2.o ../../wolfcrypt/src/md2.c   
	
${OBJECTDIR}/_ext/181168623/md4.o: ../../wolfcrypt/src/md4.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/md4.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/md4.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/md4.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/md4.o.d" -o ${OBJECTDIR}/_ext/181168623/md4.o ../../wolfcrypt/src/md4.c   
	
${OBJECTDIR}/_ext/181168623/md5.o: ../../wolfcrypt/src/md5.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/md5.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/md5.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/md5.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/md5.o.d" -o ${OBJECTDIR}/_ext/181168623/md5.o ../../wolfcrypt/src/md5.c   
	
${OBJECTDIR}/_ext/181168623/memory.o: ../../wolfcrypt/src/memory.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/memory.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/memory.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/memory.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/memory.o.d" -o ${OBJECTDIR}/_ext/181168623/memory.o ../../wolfcrypt/src/memory.c   
	
${OBJECTDIR}/_ext/181168623/misc.o: ../../wolfcrypt/src/misc.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/misc.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/misc.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/misc.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/misc.o.d" -o ${OBJECTDIR}/_ext/181168623/misc.o ../../wolfcrypt/src/misc.c   
	
${OBJECTDIR}/_ext/181168623/pkcs7.o: ../../wolfcrypt/src/pkcs7.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/pkcs7.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/pkcs7.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/pkcs7.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/pkcs7.o.d" -o ${OBJECTDIR}/_ext/181168623/pkcs7.o ../../wolfcrypt/src/pkcs7.c   
	
${OBJECTDIR}/_ext/181168623/poly1305.o: ../../wolfcrypt/src/poly1305.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/poly1305.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/poly1305.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/poly1305.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/poly1305.o.d" -o ${OBJECTDIR}/_ext/181168623/poly1305.o ../../wolfcrypt/src/poly1305.c   
	
${OBJECTDIR}/_ext/181168623/pwdbased.o: ../../wolfcrypt/src/pwdbased.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/pwdbased.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/pwdbased.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/pwdbased.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/pwdbased.o.d" -o ${OBJECTDIR}/_ext/181168623/pwdbased.o ../../wolfcrypt/src/pwdbased.c   
	
${OBJECTDIR}/_ext/181168623/rabbit.o: ../../wolfcrypt/src/rabbit.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/rabbit.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/rabbit.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/rabbit.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/rabbit.o.d" -o ${OBJECTDIR}/_ext/181168623/rabbit.o ../../wolfcrypt/src/rabbit.c   
	
${OBJECTDIR}/_ext/181168623/random.o: ../../wolfcrypt/src/random.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/random.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/random.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/random.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/random.o.d" -o ${OBJECTDIR}/_ext/181168623/random.o ../../wolfcrypt/src/random.c   
	
${OBJECTDIR}/_ext/181168623/ripemd.o: ../../wolfcrypt/src/ripemd.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/ripemd.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/ripemd.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/ripemd.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/ripemd.o.d" -o ${OBJECTDIR}/_ext/181168623/ripemd.o ../../wolfcrypt/src/ripemd.c   
	
${OBJECTDIR}/_ext/181168623/rsa.o: ../../wolfcrypt/src/rsa.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/rsa.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/rsa.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/rsa.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/rsa.o.d" -o ${OBJECTDIR}/_ext/181168623/rsa.o ../../wolfcrypt/src/rsa.c   
	
${OBJECTDIR}/_ext/181168623/sha.o: ../../wolfcrypt/src/sha.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/sha.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/sha.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/sha.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/sha.o.d" -o ${OBJECTDIR}/_ext/181168623/sha.o ../../wolfcrypt/src/sha.c   
	
${OBJECTDIR}/_ext/181168623/sha256.o: ../../wolfcrypt/src/sha256.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/sha256.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/sha256.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/sha256.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/sha256.o.d" -o ${OBJECTDIR}/_ext/181168623/sha256.o ../../wolfcrypt/src/sha256.c   
	
${OBJECTDIR}/_ext/181168623/sha512.o: ../../wolfcrypt/src/sha512.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/sha512.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/sha512.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/sha512.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/sha512.o.d" -o ${OBJECTDIR}/_ext/181168623/sha512.o ../../wolfcrypt/src/sha512.c   
	
${OBJECTDIR}/_ext/181168623/tfm.o: ../../wolfcrypt/src/tfm.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/tfm.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/tfm.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/tfm.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/tfm.o.d" -o ${OBJECTDIR}/_ext/181168623/tfm.o ../../wolfcrypt/src/tfm.c   
	
${OBJECTDIR}/_ext/181168623/wc_port.o: ../../wolfcrypt/src/wc_port.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/wc_port.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/wc_port.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/wc_port.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/wc_port.o.d" -o ${OBJECTDIR}/_ext/181168623/wc_port.o ../../wolfcrypt/src/wc_port.c   
	
${OBJECTDIR}/_ext/2020528871/pic32mz-hash.o: ../../wolfcrypt/src/port/pic32/pic32mz-hash.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/2020528871" 
	@${RM} ${OBJECTDIR}/_ext/2020528871/pic32mz-hash.o.d 
	@${RM} ${OBJECTDIR}/_ext/2020528871/pic32mz-hash.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/2020528871/pic32mz-hash.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/2020528871/pic32mz-hash.o.d" -o ${OBJECTDIR}/_ext/2020528871/pic32mz-hash.o ../../wolfcrypt/src/port/pic32/pic32mz-hash.c   
	
${OBJECTDIR}/_ext/1445274692/crl.o: ../../src/crl.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/1445274692" 
	@${RM} ${OBJECTDIR}/_ext/1445274692/crl.o.d 
	@${RM} ${OBJECTDIR}/_ext/1445274692/crl.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/1445274692/crl.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/1445274692/crl.o.d" -o ${OBJECTDIR}/_ext/1445274692/crl.o ../../src/crl.c   
	
${OBJECTDIR}/_ext/1445274692/internal.o: ../../src/internal.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/1445274692" 
	@${RM} ${OBJECTDIR}/_ext/1445274692/internal.o.d 
	@${RM} ${OBJECTDIR}/_ext/1445274692/internal.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/1445274692/internal.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/1445274692/internal.o.d" -o ${OBJECTDIR}/_ext/1445274692/internal.o ../../src/internal.c   
	
${OBJECTDIR}/_ext/1445274692/io.o: ../../src/io.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/1445274692" 
	@${RM} ${OBJECTDIR}/_ext/1445274692/io.o.d 
	@${RM} ${OBJECTDIR}/_ext/1445274692/io.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/1445274692/io.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/1445274692/io.o.d" -o ${OBJECTDIR}/_ext/1445274692/io.o ../../src/io.c   
	
${OBJECTDIR}/_ext/1445274692/keys.o: ../../src/keys.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/1445274692" 
	@${RM} ${OBJECTDIR}/_ext/1445274692/keys.o.d 
	@${RM} ${OBJECTDIR}/_ext/1445274692/keys.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/1445274692/keys.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/1445274692/keys.o.d" -o ${OBJECTDIR}/_ext/1445274692/keys.o ../../src/keys.c   
	
${OBJECTDIR}/_ext/1445274692/ocsp.o: ../../src/ocsp.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/1445274692" 
	@${RM} ${OBJECTDIR}/_ext/1445274692/ocsp.o.d 
	@${RM} ${OBJECTDIR}/_ext/1445274692/ocsp.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/1445274692/ocsp.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/1445274692/ocsp.o.d" -o ${OBJECTDIR}/_ext/1445274692/ocsp.o ../../src/ocsp.c   
	
${OBJECTDIR}/_ext/1445274692/sniffer.o: ../../src/sniffer.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/1445274692" 
	@${RM} ${OBJECTDIR}/_ext/1445274692/sniffer.o.d 
	@${RM} ${OBJECTDIR}/_ext/1445274692/sniffer.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/1445274692/sniffer.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/1445274692/sniffer.o.d" -o ${OBJECTDIR}/_ext/1445274692/sniffer.o ../../src/sniffer.c   
	
${OBJECTDIR}/_ext/1445274692/ssl.o: ../../src/ssl.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/1445274692" 
	@${RM} ${OBJECTDIR}/_ext/1445274692/ssl.o.d 
	@${RM} ${OBJECTDIR}/_ext/1445274692/ssl.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/1445274692/ssl.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/1445274692/ssl.o.d" -o ${OBJECTDIR}/_ext/1445274692/ssl.o ../../src/ssl.c   
	
${OBJECTDIR}/_ext/1445274692/tls.o: ../../src/tls.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/1445274692" 
	@${RM} ${OBJECTDIR}/_ext/1445274692/tls.o.d 
	@${RM} ${OBJECTDIR}/_ext/1445274692/tls.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/1445274692/tls.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE) -g -D__DEBUG -D__MPLAB_DEBUGGER_PK3=1 -fframe-base-loclist  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/1445274692/tls.o.d" -o ${OBJECTDIR}/_ext/1445274692/tls.o ../../src/tls.c   
	
else
${OBJECTDIR}/_ext/181168623/aes.o: ../../wolfcrypt/src/aes.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/aes.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/aes.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/aes.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/aes.o.d" -o ${OBJECTDIR}/_ext/181168623/aes.o ../../wolfcrypt/src/aes.c   
	
${OBJECTDIR}/_ext/181168623/arc4.o: ../../wolfcrypt/src/arc4.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/arc4.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/arc4.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/arc4.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/arc4.o.d" -o ${OBJECTDIR}/_ext/181168623/arc4.o ../../wolfcrypt/src/arc4.c   
	
${OBJECTDIR}/_ext/181168623/asm.o: ../../wolfcrypt/src/asm.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/asm.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/asm.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/asm.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/asm.o.d" -o ${OBJECTDIR}/_ext/181168623/asm.o ../../wolfcrypt/src/asm.c   
	
${OBJECTDIR}/_ext/181168623/asn.o: ../../wolfcrypt/src/asn.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/asn.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/asn.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/asn.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/asn.o.d" -o ${OBJECTDIR}/_ext/181168623/asn.o ../../wolfcrypt/src/asn.c   
	
${OBJECTDIR}/_ext/181168623/blake2b.o: ../../wolfcrypt/src/blake2b.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/blake2b.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/blake2b.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/blake2b.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/blake2b.o.d" -o ${OBJECTDIR}/_ext/181168623/blake2b.o ../../wolfcrypt/src/blake2b.c   
	
${OBJECTDIR}/_ext/181168623/camellia.o: ../../wolfcrypt/src/camellia.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/camellia.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/camellia.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/camellia.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/camellia.o.d" -o ${OBJECTDIR}/_ext/181168623/camellia.o ../../wolfcrypt/src/camellia.c   
	
${OBJECTDIR}/_ext/181168623/chacha.o: ../../wolfcrypt/src/chacha.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/chacha.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/chacha.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/chacha.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/chacha.o.d" -o ${OBJECTDIR}/_ext/181168623/chacha.o ../../wolfcrypt/src/chacha.c   
	
${OBJECTDIR}/_ext/181168623/coding.o: ../../wolfcrypt/src/coding.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/coding.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/coding.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/coding.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/coding.o.d" -o ${OBJECTDIR}/_ext/181168623/coding.o ../../wolfcrypt/src/coding.c   
	
${OBJECTDIR}/_ext/181168623/compress.o: ../../wolfcrypt/src/compress.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/compress.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/compress.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/compress.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/compress.o.d" -o ${OBJECTDIR}/_ext/181168623/compress.o ../../wolfcrypt/src/compress.c   
	
${OBJECTDIR}/_ext/181168623/des3.o: ../../wolfcrypt/src/des3.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/des3.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/des3.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/des3.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/des3.o.d" -o ${OBJECTDIR}/_ext/181168623/des3.o ../../wolfcrypt/src/des3.c   
	
${OBJECTDIR}/_ext/181168623/dh.o: ../../wolfcrypt/src/dh.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/dh.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/dh.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/dh.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/dh.o.d" -o ${OBJECTDIR}/_ext/181168623/dh.o ../../wolfcrypt/src/dh.c   
	
${OBJECTDIR}/_ext/181168623/dsa.o: ../../wolfcrypt/src/dsa.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/dsa.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/dsa.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/dsa.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/dsa.o.d" -o ${OBJECTDIR}/_ext/181168623/dsa.o ../../wolfcrypt/src/dsa.c   
	
${OBJECTDIR}/_ext/181168623/ecc.o: ../../wolfcrypt/src/ecc.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/ecc.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/ecc.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/ecc.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/ecc.o.d" -o ${OBJECTDIR}/_ext/181168623/ecc.o ../../wolfcrypt/src/ecc.c   
	
${OBJECTDIR}/_ext/181168623/ecc_fp.o: ../../wolfcrypt/src/ecc_fp.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/ecc_fp.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/ecc_fp.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/ecc_fp.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/ecc_fp.o.d" -o ${OBJECTDIR}/_ext/181168623/ecc_fp.o ../../wolfcrypt/src/ecc_fp.c   
	
${OBJECTDIR}/_ext/181168623/error.o: ../../wolfcrypt/src/error.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/error.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/error.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/error.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/error.o.d" -o ${OBJECTDIR}/_ext/181168623/error.o ../../wolfcrypt/src/error.c   
	
${OBJECTDIR}/_ext/181168623/hc128.o: ../../wolfcrypt/src/hc128.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/hc128.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/hc128.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/hc128.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/hc128.o.d" -o ${OBJECTDIR}/_ext/181168623/hc128.o ../../wolfcrypt/src/hc128.c   
	
${OBJECTDIR}/_ext/181168623/hmac.o: ../../wolfcrypt/src/hmac.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/hmac.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/hmac.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/hmac.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/hmac.o.d" -o ${OBJECTDIR}/_ext/181168623/hmac.o ../../wolfcrypt/src/hmac.c   
	
${OBJECTDIR}/_ext/181168623/integer.o: ../../wolfcrypt/src/integer.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/integer.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/integer.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/integer.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/integer.o.d" -o ${OBJECTDIR}/_ext/181168623/integer.o ../../wolfcrypt/src/integer.c   
	
${OBJECTDIR}/_ext/181168623/logging.o: ../../wolfcrypt/src/logging.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/logging.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/logging.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/logging.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/logging.o.d" -o ${OBJECTDIR}/_ext/181168623/logging.o ../../wolfcrypt/src/logging.c   
	
${OBJECTDIR}/_ext/181168623/md2.o: ../../wolfcrypt/src/md2.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/md2.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/md2.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/md2.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/md2.o.d" -o ${OBJECTDIR}/_ext/181168623/md2.o ../../wolfcrypt/src/md2.c   
	
${OBJECTDIR}/_ext/181168623/md4.o: ../../wolfcrypt/src/md4.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/md4.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/md4.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/md4.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/md4.o.d" -o ${OBJECTDIR}/_ext/181168623/md4.o ../../wolfcrypt/src/md4.c   
	
${OBJECTDIR}/_ext/181168623/md5.o: ../../wolfcrypt/src/md5.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/md5.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/md5.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/md5.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/md5.o.d" -o ${OBJECTDIR}/_ext/181168623/md5.o ../../wolfcrypt/src/md5.c   
	
${OBJECTDIR}/_ext/181168623/memory.o: ../../wolfcrypt/src/memory.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/memory.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/memory.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/memory.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/memory.o.d" -o ${OBJECTDIR}/_ext/181168623/memory.o ../../wolfcrypt/src/memory.c   
	
${OBJECTDIR}/_ext/181168623/misc.o: ../../wolfcrypt/src/misc.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/misc.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/misc.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/misc.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/misc.o.d" -o ${OBJECTDIR}/_ext/181168623/misc.o ../../wolfcrypt/src/misc.c   
	
${OBJECTDIR}/_ext/181168623/pkcs7.o: ../../wolfcrypt/src/pkcs7.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/pkcs7.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/pkcs7.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/pkcs7.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/pkcs7.o.d" -o ${OBJECTDIR}/_ext/181168623/pkcs7.o ../../wolfcrypt/src/pkcs7.c   
	
${OBJECTDIR}/_ext/181168623/poly1305.o: ../../wolfcrypt/src/poly1305.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/poly1305.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/poly1305.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/poly1305.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/poly1305.o.d" -o ${OBJECTDIR}/_ext/181168623/poly1305.o ../../wolfcrypt/src/poly1305.c   
	
${OBJECTDIR}/_ext/181168623/pwdbased.o: ../../wolfcrypt/src/pwdbased.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/pwdbased.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/pwdbased.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/pwdbased.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/pwdbased.o.d" -o ${OBJECTDIR}/_ext/181168623/pwdbased.o ../../wolfcrypt/src/pwdbased.c   
	
${OBJECTDIR}/_ext/181168623/rabbit.o: ../../wolfcrypt/src/rabbit.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/rabbit.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/rabbit.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/rabbit.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/rabbit.o.d" -o ${OBJECTDIR}/_ext/181168623/rabbit.o ../../wolfcrypt/src/rabbit.c   
	
${OBJECTDIR}/_ext/181168623/random.o: ../../wolfcrypt/src/random.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/random.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/random.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/random.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/random.o.d" -o ${OBJECTDIR}/_ext/181168623/random.o ../../wolfcrypt/src/random.c   
	
${OBJECTDIR}/_ext/181168623/ripemd.o: ../../wolfcrypt/src/ripemd.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/ripemd.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/ripemd.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/ripemd.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/ripemd.o.d" -o ${OBJECTDIR}/_ext/181168623/ripemd.o ../../wolfcrypt/src/ripemd.c   
	
${OBJECTDIR}/_ext/181168623/rsa.o: ../../wolfcrypt/src/rsa.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/rsa.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/rsa.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/rsa.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/rsa.o.d" -o ${OBJECTDIR}/_ext/181168623/rsa.o ../../wolfcrypt/src/rsa.c   
	
${OBJECTDIR}/_ext/181168623/sha.o: ../../wolfcrypt/src/sha.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/sha.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/sha.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/sha.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/sha.o.d" -o ${OBJECTDIR}/_ext/181168623/sha.o ../../wolfcrypt/src/sha.c   
	
${OBJECTDIR}/_ext/181168623/sha256.o: ../../wolfcrypt/src/sha256.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/sha256.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/sha256.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/sha256.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/sha256.o.d" -o ${OBJECTDIR}/_ext/181168623/sha256.o ../../wolfcrypt/src/sha256.c   
	
${OBJECTDIR}/_ext/181168623/sha512.o: ../../wolfcrypt/src/sha512.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/sha512.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/sha512.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/sha512.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/sha512.o.d" -o ${OBJECTDIR}/_ext/181168623/sha512.o ../../wolfcrypt/src/sha512.c   
	
${OBJECTDIR}/_ext/181168623/tfm.o: ../../wolfcrypt/src/tfm.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/tfm.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/tfm.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/tfm.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/tfm.o.d" -o ${OBJECTDIR}/_ext/181168623/tfm.o ../../wolfcrypt/src/tfm.c   
	
${OBJECTDIR}/_ext/181168623/wc_port.o: ../../wolfcrypt/src/wc_port.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/181168623" 
	@${RM} ${OBJECTDIR}/_ext/181168623/wc_port.o.d 
	@${RM} ${OBJECTDIR}/_ext/181168623/wc_port.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/181168623/wc_port.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/181168623/wc_port.o.d" -o ${OBJECTDIR}/_ext/181168623/wc_port.o ../../wolfcrypt/src/wc_port.c   
	
${OBJECTDIR}/_ext/2020528871/pic32mz-hash.o: ../../wolfcrypt/src/port/pic32/pic32mz-hash.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/2020528871" 
	@${RM} ${OBJECTDIR}/_ext/2020528871/pic32mz-hash.o.d 
	@${RM} ${OBJECTDIR}/_ext/2020528871/pic32mz-hash.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/2020528871/pic32mz-hash.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/2020528871/pic32mz-hash.o.d" -o ${OBJECTDIR}/_ext/2020528871/pic32mz-hash.o ../../wolfcrypt/src/port/pic32/pic32mz-hash.c   
	
${OBJECTDIR}/_ext/1445274692/crl.o: ../../src/crl.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/1445274692" 
	@${RM} ${OBJECTDIR}/_ext/1445274692/crl.o.d 
	@${RM} ${OBJECTDIR}/_ext/1445274692/crl.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/1445274692/crl.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/1445274692/crl.o.d" -o ${OBJECTDIR}/_ext/1445274692/crl.o ../../src/crl.c   
	
${OBJECTDIR}/_ext/1445274692/internal.o: ../../src/internal.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/1445274692" 
	@${RM} ${OBJECTDIR}/_ext/1445274692/internal.o.d 
	@${RM} ${OBJECTDIR}/_ext/1445274692/internal.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/1445274692/internal.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/1445274692/internal.o.d" -o ${OBJECTDIR}/_ext/1445274692/internal.o ../../src/internal.c   
	
${OBJECTDIR}/_ext/1445274692/io.o: ../../src/io.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/1445274692" 
	@${RM} ${OBJECTDIR}/_ext/1445274692/io.o.d 
	@${RM} ${OBJECTDIR}/_ext/1445274692/io.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/1445274692/io.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/1445274692/io.o.d" -o ${OBJECTDIR}/_ext/1445274692/io.o ../../src/io.c   
	
${OBJECTDIR}/_ext/1445274692/keys.o: ../../src/keys.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/1445274692" 
	@${RM} ${OBJECTDIR}/_ext/1445274692/keys.o.d 
	@${RM} ${OBJECTDIR}/_ext/1445274692/keys.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/1445274692/keys.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/1445274692/keys.o.d" -o ${OBJECTDIR}/_ext/1445274692/keys.o ../../src/keys.c   
	
${OBJECTDIR}/_ext/1445274692/ocsp.o: ../../src/ocsp.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/1445274692" 
	@${RM} ${OBJECTDIR}/_ext/1445274692/ocsp.o.d 
	@${RM} ${OBJECTDIR}/_ext/1445274692/ocsp.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/1445274692/ocsp.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/1445274692/ocsp.o.d" -o ${OBJECTDIR}/_ext/1445274692/ocsp.o ../../src/ocsp.c   
	
${OBJECTDIR}/_ext/1445274692/sniffer.o: ../../src/sniffer.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/1445274692" 
	@${RM} ${OBJECTDIR}/_ext/1445274692/sniffer.o.d 
	@${RM} ${OBJECTDIR}/_ext/1445274692/sniffer.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/1445274692/sniffer.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/1445274692/sniffer.o.d" -o ${OBJECTDIR}/_ext/1445274692/sniffer.o ../../src/sniffer.c   
	
${OBJECTDIR}/_ext/1445274692/ssl.o: ../../src/ssl.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/1445274692" 
	@${RM} ${OBJECTDIR}/_ext/1445274692/ssl.o.d 
	@${RM} ${OBJECTDIR}/_ext/1445274692/ssl.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/1445274692/ssl.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/1445274692/ssl.o.d" -o ${OBJECTDIR}/_ext/1445274692/ssl.o ../../src/ssl.c   
	
${OBJECTDIR}/_ext/1445274692/tls.o: ../../src/tls.c  nbproject/Makefile-${CND_CONF}.mk
	@${MKDIR} "${OBJECTDIR}/_ext/1445274692" 
	@${RM} ${OBJECTDIR}/_ext/1445274692/tls.o.d 
	@${RM} ${OBJECTDIR}/_ext/1445274692/tls.o 
	@${FIXDEPS} "${OBJECTDIR}/_ext/1445274692/tls.o.d" $(SILENT) -rsi ${MP_CC_DIR}../  -c ${MP_CC}  $(MP_EXTRA_CC_PRE)  -x c -c -mprocessor=$(MP_PROCESSOR_OPTION)  -O3 -DWOLFSSL_SHA512 -DWOLFSSL_SHA384 -DHAVE_ECC -I"../../" -I"../" -MMD -MF "${OBJECTDIR}/_ext/1445274692/tls.o.d" -o ${OBJECTDIR}/_ext/1445274692/tls.o ../../src/tls.c   
	
endif

# ------------------------------------------------------------------------------------
# Rules for buildStep: compileCPP
ifeq ($(TYPE_IMAGE), DEBUG_RUN)
else
endif

# ------------------------------------------------------------------------------------
# Rules for buildStep: archive
ifeq ($(TYPE_IMAGE), DEBUG_RUN)
dist/${CND_CONF}/${IMAGE_TYPE}/wolfssl.X.${OUTPUT_SUFFIX}: ${OBJECTFILES}  nbproject/Makefile-${CND_CONF}.mk    
	@${MKDIR} dist/${CND_CONF}/${IMAGE_TYPE} 
	${MP_AR} $(MP_EXTRA_AR_PRE) r dist/${CND_CONF}/${IMAGE_TYPE}/wolfssl.X.${OUTPUT_SUFFIX} ${OBJECTFILES_QUOTED_IF_SPACED}    
else
dist/${CND_CONF}/${IMAGE_TYPE}/wolfssl.X.${OUTPUT_SUFFIX}: ${OBJECTFILES}  nbproject/Makefile-${CND_CONF}.mk   
	@${MKDIR} dist/${CND_CONF}/${IMAGE_TYPE} 
	${MP_AR} $(MP_EXTRA_AR_PRE) r dist/${CND_CONF}/${IMAGE_TYPE}/wolfssl.X.${OUTPUT_SUFFIX} ${OBJECTFILES_QUOTED_IF_SPACED}    
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

DEPFILES=$(shell "${PATH_TO_IDE_BIN}"mplabwildcard ${POSSIBLE_DEPFILES})
ifneq (${DEPFILES},)
include ${DEPFILES}
endif
