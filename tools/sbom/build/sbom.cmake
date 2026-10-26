# sbom.cmake - shared CMake helper for wolfssl-compliance-tooling SBOM generation.
#
# This replaces the per-product `add_custom_target(sbom ...)` blocks that today
# are copied and drifting across wolfMQTT, wolfTPM, and wolfBoot. It exposes ONE
# function, wolfssl_compliance_tooling_add_sbom(), so each product describes itself in a few lines
# and gets an `sbom` target that calls the same driver as the Make and autotools
# paths. That call also adds `install-sbom` and `uninstall-sbom`.
#
# Include this file, then call the function:
#
#   include(${CMAKE_CURRENT_SOURCE_DIR}/tools/sbom/build/sbom.cmake)
#   wolfssl_compliance_tooling_add_sbom(
#       NAME          wolfboot
#       VERSION_FILE  ${CMAKE_CURRENT_SOURCE_DIR}/include/wolfboot/version.h
#       VERSION_MACRO LIBWOLFBOOT_VERSION_STRING
#       TARGETS       wolfboot wolfboothal
#       DEFS          ${WOLFBOOT_DEFS} ${USER_SETTINGS}
#       LICENSE       ${CMAKE_CURRENT_SOURCE_DIR}/LICENSE
#   )
#
# Optional arguments:
#   SBOM_GEN <path>   Path to gen-sbom (default: driver auto-discovery).
#   GEN_SBOM <path>   Legacy alias for SBOM_GEN.
#   HOSTCC   <bin>    Host C compiler for macro capture (default: cc).
#   ROOT     <dir>    Product root (default: CMAKE_CURRENT_SOURCE_DIR).
#   TARGET_NAME <n>   Name of the custom target (default: sbom).
#   CDX_OUT  <path>   Explicit CycloneDX output path.
#   SPDX_OUT <path>   Explicit SPDX output path.
#   COMPONENT_TYPE <t>  CycloneDX component.type, e.g. firmware for a
#                     bootloader (default: the generator's own default).
#   COPYRIGHT_START <year>  First year of the copyright line (default: 2006).
#   SETTINGS_H <path> Settings header included in the macro capture, so DEFS
#                     are interpreted by the header that derives from them.
#                     Without it the capture sees the -D list alone and every
#                     derived macro (WOLFCRYPT_ONLY and friends) is missing,
#                     which is how the CMake path used to record a different
#                     configuration than the Make path for the same product.
#   INCLUDE_DIRS <dir>...  Include directories for that capture (typically the
#                     directory holding user_settings.h).
#   DEP_WOLFSSL yes|no  Record wolfSSL as a dependency component.
#   DEP_WOLFCRYPT yes|no  Record wolfCrypt as a nested component (PURL;
#                         matching uses the wolfssl CPE).
#   DEP_OPENSSL yes|no  Record OpenSSL as a dependency component.
#   DEP_LIBZ yes|no   Record zlib. Pass the product's real option. The
#                     default in gen-sbom is no.
#   DOCUMENT_NAMESPACE <uri>  SPDX documentNamespace. Default is a
#                     deterministic urn:uuid from the generator.
#   CRYPTO_ONLY auto|yes|no  Whether only the wolfCrypt subset of wolfSSL is
#                     compiled in (default auto: read from the capture).
#   DEP_VERSION <KEY=VER>...  Explicit dependency versions. A cross build has
#                     no pkg-config for the dependency, so without this the
#                     dependency component carries no version, and therefore
#                     no PURL and no CPE for a scanner to match.
#   LICENSE_OVERRIDE <expr>  SPDX expression recorded instead of the one
#                     inferred from LICENSE.
#   LICENSE_TEXT <path>  Plain-text licence for a LicenseRef-* used in
#                     LICENSE_OVERRIDE (required by SPDX 2.3).
#   NO_ARTIFACT_HASH      Record a placeholder checksum. Do not pass TARGETS
#                     or LIB with this option.
#
#   USER_SETTINGS <path>  Path to wolfssl/wolfcrypt/settings.h. This is the
#                     generator's pcpp entry point. Also pass
#                     USER_SETTINGS_INCLUDE and USER_SETTINGS_DEFINE
#                     WOLFSSL_USER_SETTINGS. A user_settings.h path alone
#                     records only the literals in that file.
#   USER_SETTINGS_INCLUDE <dir>...  Directories for that preprocess. One of
#                     them must contain user_settings.h.
#   USER_SETTINGS_DEFINE <NAME[=VALUE]>...  Predefines for that preprocess.
#                     Include WOLFSSL_USER_SETTINGS.
#   TV_OUT <path>     SPDX tag-value file, when a later step writes one.
#   INSTALL_DIR <dir> Doc directory for install-sbom. Default:
#                     CMAKE_INSTALL_FULL_DOCDIR, else
#                     <prefix>/share/doc/<NAME>.
#   INSTALL_DEPENDS <target>  Target that produces the files. Default:
#                     TARGET_NAME. wolfTPM builds the tag-value file in a
#                     later target named sbom, so that product passes
#                     NO_INSTALL here and calls wolfssl_compliance_tooling_add_sbom_install()
#                     after that target exists.
#   NO_INSTALL        Do not create install-sbom / uninstall-sbom.
#   INSTALL_TARGET <n>    Name of the install target (default: install-sbom).
#   UNINSTALL_TARGET <n>  Name of the uninstall target (default: uninstall-sbom).
#                     A second call in the same tree sets both.
#
# wolfssl_compliance_tooling_add_sbom() also creates install-sbom and uninstall-sbom.
# install-sbom reads DESTDIR when the target runs. Output paths are the
# caller's CDX_OUT and SPDX_OUT, so a wolfBoot config tag is installed
# under that name. The tag-value file is installed only when TV_OUT is
# set and the file exists. uninstall-sbom removes the same paths.
#
# These mirror the SBOM_* variables of build/sbom.mk one for one; the two
# fragments must accept the same product description, or the same product
# yields two different documents depending on which build system generated it.
#
# The helper runs sbom-driver.py with the Python interpreter. A native
# Windows CMake generator cannot start the extensionless sbom-driver shell
# wrapper. That wrapper remains the Make and shell entry point.

# The shared driver sits one directory above this fragment.
set(_WOLFSSL_COMPLIANCE_TOOLING_SBOM_DIR ${CMAKE_CURRENT_LIST_DIR})
get_filename_component(_WOLFSSL_COMPLIANCE_TOOLING_DRIVER
    "${_WOLFSSL_COMPLIANCE_TOOLING_SBOM_DIR}/../sbom-driver.py" ABSOLUTE)
find_package(Python3 COMPONENTS Interpreter)

function(wolfssl_compliance_tooling_add_sbom)
    set(_opts NO_ARTIFACT_HASH SOURCE_ONLY NO_INSTALL)
    set(_one NAME TARGET_NAME VERSION VERSION_FILE VERSION_MACRO LICENSE
             SBOM_GEN GEN_SBOM HOSTCC ROOT LIB USER_SETTINGS OPTIONS_H SETTINGS_H
             DEP_WOLFSSL DEP_WOLFCRYPT DEP_OPENSSL DEP_LIBZ CRYPTO_ONLY
             CDX_OUT SPDX_OUT TV_OUT COMPONENT_TYPE DOCUMENT_NAMESPACE
             COPYRIGHT_START
             LICENSE_OVERRIDE LICENSE_TEXT
             INSTALL_DIR INSTALL_DEPENDS INSTALL_TARGET UNINSTALL_TARGET)
    set(_multi TARGETS DEFS DEP_VERSION INCLUDE_DIRS
             USER_SETTINGS_INCLUDE USER_SETTINGS_DEFINE)
    cmake_parse_arguments(SB "${_opts}" "${_one}" "${_multi}" ${ARGN})

    if(NOT SB_NAME)
        message(FATAL_ERROR "wolfssl_compliance_tooling_add_sbom: NAME is required")
    endif()
    if(SB_NO_ARTIFACT_HASH)
        if(SB_TARGETS OR SB_LIB)
            message(FATAL_ERROR
                "wolfssl_compliance_tooling_add_sbom: NO_ARTIFACT_HASH stands "
                "alone. Do not pass TARGETS or LIB.")
        endif()
    elseif(NOT SB_TARGETS AND NOT SB_LIB)
        message(FATAL_ERROR "wolfssl_compliance_tooling_add_sbom: set TARGETS or LIB")
    endif()
    if(NOT SB_ROOT)
        set(SB_ROOT ${CMAKE_CURRENT_SOURCE_DIR})
    endif()
    if(NOT SB_LICENSE)
        set(SB_LICENSE ${SB_ROOT}/LICENSE)
    endif()
    if(NOT SB_HOSTCC)
        set(SB_HOSTCC cc)
    endif()
    if(NOT SB_TARGET_NAME)
        set(SB_TARGET_NAME sbom)
    endif()
    if(NOT SB_SBOM_GEN AND SB_GEN_SBOM)
        set(SB_SBOM_GEN ${SB_GEN_SBOM})
    endif()

    # Collect the compiled source set from the named targets. Skip generator
    # expressions and headers so the list matches the Make path (compiled
    # translation units only).
    set(_srcs "")
    foreach(_t IN LISTS SB_TARGETS)
        if(TARGET ${_t})
            get_target_property(_t_srcs ${_t} SOURCES)
            get_target_property(_t_dir ${_t} SOURCE_DIR)
            if(_t_srcs)
                foreach(_s IN LISTS _t_srcs)
                    if(NOT _s MATCHES "\\$<" AND
                       _s MATCHES "\\.(c|cc|cpp|cxx|s|S|asm)$")
                        if(IS_ABSOLUTE "${_s}")
                            list(APPEND _srcs "${_s}")
                        else()
                            list(APPEND _srcs "${_t_dir}/${_s}")
                        endif()
                    endif()
                endforeach()
            endif()
        endif()
    endforeach()
    list(REMOVE_DUPLICATES _srcs)

    if(NOT Python3_EXECUTABLE)
        message(FATAL_ERROR
            "wolfssl_compliance_tooling_add_sbom: python3 was not found")
    endif()

    set(_cmd ${CMAKE_COMMAND} -E env HOSTCC=${SB_HOSTCC}
             ${Python3_EXECUTABLE}
             ${_WOLFSSL_COMPLIANCE_TOOLING_DRIVER}
             --name ${SB_NAME}
             --root ${SB_ROOT}
             --license-file ${SB_LICENSE}
             --hostcc ${SB_HOSTCC}
             --skip-missing)

    # Composition: one checksum source. NO_ARTIFACT_HASH stands alone.
    if(SB_NO_ARTIFACT_HASH)
        list(APPEND _cmd --no-artifact-hash)
    else()
        if(SB_TARGETS)
            set(_srcs_file ${CMAKE_CURRENT_BINARY_DIR}/${SB_NAME}-sbom-srcs.txt)
            string(REPLACE ";" "\n" _srcs_nl "${_srcs}")
            file(GENERATE OUTPUT ${_srcs_file} CONTENT "${_srcs_nl}\n")
            list(APPEND _cmd --srcs-file ${_srcs_file})
        endif()
        if(SB_LIB)
            list(APPEND _cmd --lib ${SB_LIB})
        endif()
    endif()

    # Config: user_settings, a pre-expanded header, source-only, or -D flags.
    if(SB_USER_SETTINGS)
        list(APPEND _cmd --user-settings ${SB_USER_SETTINGS})
        foreach(_inc IN LISTS SB_USER_SETTINGS_INCLUDE)
            list(APPEND _cmd --user-settings-include ${_inc})
        endforeach()
        foreach(_def IN LISTS SB_USER_SETTINGS_DEFINE)
            list(APPEND _cmd --user-settings-define ${_def})
        endforeach()
    elseif(SB_OPTIONS_H)
        list(APPEND _cmd --options-h ${SB_OPTIONS_H})
    elseif(SB_SOURCE_ONLY)
        list(APPEND _cmd --source-only)
    else()
        set(_cflags "")
        list(REMOVE_DUPLICATES SB_DEFS)
        foreach(_d IN LISTS SB_DEFS)
            if(NOT _d STREQUAL "")
                string(REGEX REPLACE "^-D" "" _d "${_d}")
                set(_cflags "${_cflags} -D${_d}")
            endif()
        endforeach()
        string(STRIP "${_cflags}" _cflags)
        list(APPEND _cmd "--cflags=${_cflags}")
        # Only meaningful alongside --cflags: the driver warns and ignores
        # them otherwise.
        if(SB_SETTINGS_H)
            list(APPEND _cmd --settings-h ${SB_SETTINGS_H})
        endif()
        foreach(_inc IN LISTS SB_INCLUDE_DIRS)
            list(APPEND _cmd --include-dir ${_inc})
        endforeach()
    endif()

    if(SB_VERSION)
        # CMake before 3.24 parses options after -P and treats a separate
        # "--version" as its own flag. One argument keeps the driver version.
        list(APPEND _cmd --version=${SB_VERSION})
    endif()
    if(SB_VERSION_FILE)
        list(APPEND _cmd --version-file ${SB_VERSION_FILE})
    endif()
    if(SB_VERSION_MACRO)
        list(APPEND _cmd --version-macro ${SB_VERSION_MACRO})
    endif()
    if(SB_COMPONENT_TYPE)
        list(APPEND _cmd --component-type ${SB_COMPONENT_TYPE})
    endif()
    if(NOT "${SB_COPYRIGHT_START}" STREQUAL "")
        list(APPEND _cmd --copyright-start ${SB_COPYRIGHT_START})
    endif()
    if(SB_LICENSE_OVERRIDE)
        list(APPEND _cmd --license-override ${SB_LICENSE_OVERRIDE})
    endif()
    if(SB_LICENSE_TEXT)
        list(APPEND _cmd --license-text ${SB_LICENSE_TEXT})
    endif()
    if(SB_DOCUMENT_NAMESPACE)
        list(APPEND _cmd --document-namespace ${SB_DOCUMENT_NAMESPACE})
    endif()
    # cmake_parse_arguments leaves an omitted keyword undefined. An
    # unquoted name then compares as the literal "SB_DEP_*", which is not
    # empty, and the flag is appended with no value. Quote the expansion.
    # "no" stays a real value and is forwarded.
    if(NOT "${SB_DEP_WOLFSSL}" STREQUAL "")
        list(APPEND _cmd --dep-wolfssl "${SB_DEP_WOLFSSL}")
    endif()
    if(NOT "${SB_DEP_WOLFCRYPT}" STREQUAL "")
        list(APPEND _cmd --dep-wolfcrypt "${SB_DEP_WOLFCRYPT}")
    endif()
    if(NOT "${SB_DEP_OPENSSL}" STREQUAL "")
        list(APPEND _cmd --dep-openssl "${SB_DEP_OPENSSL}")
    endif()
    if(NOT "${SB_DEP_LIBZ}" STREQUAL "")
        list(APPEND _cmd --dep-libz "${SB_DEP_LIBZ}")
    endif()
    if(NOT "${SB_CRYPTO_ONLY}" STREQUAL "")
        list(APPEND _cmd --crypto-only "${SB_CRYPTO_ONLY}")
    endif()
    foreach(_dv IN LISTS SB_DEP_VERSION)
        list(APPEND _cmd --dep-version ${_dv})
    endforeach()
    if(SB_SBOM_GEN)
        list(APPEND _cmd --gen-sbom ${SB_SBOM_GEN})
    endif()
    # A literal version makes the output path known here. Pass it through so
    # install-sbom copies the same file the driver writes. A version read
    # from a header stays a build-time name; the install script reads that
    # header with the same macro.
    if(NOT SB_CDX_OUT AND SB_VERSION)
        set(SB_CDX_OUT
            "${CMAKE_CURRENT_BINARY_DIR}/${SB_NAME}-${SB_VERSION}.cdx.json")
    endif()
    if(NOT SB_SPDX_OUT AND SB_VERSION)
        set(SB_SPDX_OUT
            "${CMAKE_CURRENT_BINARY_DIR}/${SB_NAME}-${SB_VERSION}.spdx.json")
    endif()
    if(SB_CDX_OUT)
        list(APPEND _cmd --cdx-out ${SB_CDX_OUT})
    endif()
    if(SB_SPDX_OUT)
        list(APPEND _cmd --spdx-out ${SB_SPDX_OUT})
    endif()

    # SOURCE_DATE_EPOCH is applied when the target runs. A value set only
    # for the build is kept. Git supplies the commit time only when the
    # variable is empty. Configure time does not freeze it.
    add_custom_target(${SB_TARGET_NAME}
        COMMAND ${CMAKE_COMMAND}
            -DSBOM_ROOT=${SB_ROOT}
            -P "${_WOLFSSL_COMPLIANCE_TOOLING_SBOM_DIR}/sbom-with-sde.cmake"
            --
            ${_cmd}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        VERBATIM
        COMMENT "Generating ${SB_NAME} SBOM (CycloneDX 1.6 + SPDX 2.3)")

    if(NOT SB_NO_INSTALL)
        set(_install_depends ${SB_TARGET_NAME})
        if(SB_INSTALL_DEPENDS)
            set(_install_depends ${SB_INSTALL_DEPENDS})
        endif()
        wolfssl_compliance_tooling_add_sbom_install(
            NAME ${SB_NAME}
            DEPENDS ${_install_depends}
            CDX "${SB_CDX_OUT}"
            SPDX "${SB_SPDX_OUT}"
            TV "${SB_TV_OUT}"
            VERSION "${SB_VERSION}"
            VERSION_FILE "${SB_VERSION_FILE}"
            VERSION_MACRO "${SB_VERSION_MACRO}"
            BINDIR "${CMAKE_CURRENT_BINARY_DIR}"
            INSTALL_DIR "${SB_INSTALL_DIR}"
            INSTALL_TARGET "${SB_INSTALL_TARGET}"
            UNINSTALL_TARGET "${SB_UNINSTALL_TARGET}")
    endif()
endfunction()

# Install and uninstall the files from one wolfssl_compliance_tooling_add_sbom() call.
# Call this directly when the files are produced by a target that does not
# exist yet inside wolfssl_compliance_tooling_add_sbom(), as wolfTPM does: the public sbom
# target validates SPDX and writes the tag-value file after the helper
# returns. Pass DEPENDS sbom and TV the tag-value path.
function(wolfssl_compliance_tooling_add_sbom_install)
    set(_one NAME DEPENDS INSTALL_DIR CDX SPDX TV VERSION VERSION_FILE
             VERSION_MACRO BINDIR INSTALL_TARGET UNINSTALL_TARGET)
    cmake_parse_arguments(SI "" "${_one}" "" ${ARGN})

    if(NOT SI_NAME)
        message(FATAL_ERROR "wolfssl_compliance_tooling_add_sbom_install: NAME is required")
    endif()
    if(NOT SI_DEPENDS)
        message(FATAL_ERROR "wolfssl_compliance_tooling_add_sbom_install: DEPENDS is required")
    endif()
    if(NOT SI_INSTALL_TARGET)
        set(SI_INSTALL_TARGET install-sbom)
    endif()
    if(NOT SI_UNINSTALL_TARGET)
        set(SI_UNINSTALL_TARGET uninstall-sbom)
    endif()
    if(TARGET ${SI_INSTALL_TARGET})
        message(FATAL_ERROR
            "wolfssl_compliance_tooling_add_sbom_install: target ${SI_INSTALL_TARGET} already exists. "
            "Pass INSTALL_TARGET for a second SBOM.")
    endif()

    if(SI_INSTALL_DIR)
        set(_docdir "${SI_INSTALL_DIR}")
    elseif(CMAKE_INSTALL_FULL_DOCDIR)
        set(_docdir "${CMAKE_INSTALL_FULL_DOCDIR}")
    else()
        set(_docdir "${CMAKE_INSTALL_PREFIX}/share/doc/${SI_NAME}")
    endif()
    if(NOT IS_ABSOLUTE "${_docdir}")
        set(_docdir "${CMAKE_INSTALL_PREFIX}/${_docdir}")
    endif()

    add_custom_target(${SI_INSTALL_TARGET}
        COMMAND ${CMAKE_COMMAND}
            -DWOLFSSL_COMPLIANCE_TOOLING_INSTALL_DIR=${_docdir}
            -DWOLFSSL_COMPLIANCE_TOOLING_SBOM_CDX=${SI_CDX}
            -DWOLFSSL_COMPLIANCE_TOOLING_SBOM_SPDX=${SI_SPDX}
            -DWOLFSSL_COMPLIANCE_TOOLING_SBOM_TV=${SI_TV}
            -DWOLFSSL_COMPLIANCE_TOOLING_SBOM_NAME=${SI_NAME}
            -DWOLFSSL_COMPLIANCE_TOOLING_SBOM_VERSION=${SI_VERSION}
            -DWOLFSSL_COMPLIANCE_TOOLING_SBOM_VERSION_FILE=${SI_VERSION_FILE}
            -DWOLFSSL_COMPLIANCE_TOOLING_SBOM_VERSION_MACRO=${SI_VERSION_MACRO}
            -DWOLFSSL_COMPLIANCE_TOOLING_SBOM_BINDIR=${SI_BINDIR}
            -P "${_WOLFSSL_COMPLIANCE_TOOLING_SBOM_DIR}/install-sbom.cmake"
        VERBATIM
        COMMENT "Installing ${SI_NAME} SBOM to ${_docdir}")
    add_dependencies(${SI_INSTALL_TARGET} ${SI_DEPENDS})

    add_custom_target(${SI_UNINSTALL_TARGET}
        COMMAND ${CMAKE_COMMAND}
            -DWOLFSSL_COMPLIANCE_TOOLING_INSTALL_DIR=${_docdir}
            -DWOLFSSL_COMPLIANCE_TOOLING_SBOM_CDX=${SI_CDX}
            -DWOLFSSL_COMPLIANCE_TOOLING_SBOM_SPDX=${SI_SPDX}
            -DWOLFSSL_COMPLIANCE_TOOLING_SBOM_TV=${SI_TV}
            -DWOLFSSL_COMPLIANCE_TOOLING_SBOM_NAME=${SI_NAME}
            -DWOLFSSL_COMPLIANCE_TOOLING_SBOM_VERSION=${SI_VERSION}
            -DWOLFSSL_COMPLIANCE_TOOLING_SBOM_VERSION_FILE=${SI_VERSION_FILE}
            -DWOLFSSL_COMPLIANCE_TOOLING_SBOM_VERSION_MACRO=${SI_VERSION_MACRO}
            -DWOLFSSL_COMPLIANCE_TOOLING_SBOM_BINDIR=${SI_BINDIR}
            -P "${_WOLFSSL_COMPLIANCE_TOOLING_SBOM_DIR}/uninstall-sbom.cmake"
        VERBATIM
        COMMENT "Uninstalling ${SI_NAME} SBOM from ${_docdir}")
endfunction()
