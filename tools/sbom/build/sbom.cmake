# sbom.cmake - shared CMake helper for wolfssl-compliance-tooling SBOM generation.
#
# This replaces the per-product `add_custom_target(sbom ...)` blocks that today
# are copied and drifting across wolfMQTT, wolfTPM, and wolfBoot. It exposes ONE
# function, wolfssl_compliance_tooling_add_sbom(), so each product describes itself in a few lines
# and gets an `sbom` target that calls the same driver as the Make and autotools
# paths.
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
#
# These mirror the SBOM_* variables of build/sbom.mk one for one; the two
# fragments must accept the same product description, or the same product
# yields two different documents depending on which build system generated it.
#
# NOTE: the driver is invoked as a program; on Windows run the target from a
# shell environment (WSL/MSYS/Git-Bash) or use the Make/autotools path.

# The shared driver sits one directory above this fragment.
set(_WOLFSSL_COMPLIANCE_TOOLING_SBOM_DIR ${CMAKE_CURRENT_LIST_DIR})
get_filename_component(_WOLFSSL_COMPLIANCE_TOOLING_DRIVER
    "${_WOLFSSL_COMPLIANCE_TOOLING_SBOM_DIR}/../sbom-driver" ABSOLUTE)

function(wolfssl_compliance_tooling_add_sbom)
    set(_opts NO_ARTIFACT_HASH SOURCE_ONLY)
    set(_one NAME TARGET_NAME VERSION VERSION_FILE VERSION_MACRO LICENSE
             SBOM_GEN GEN_SBOM HOSTCC ROOT LIB USER_SETTINGS OPTIONS_H SETTINGS_H
             DEP_WOLFSSL DEP_WOLFCRYPT DEP_OPENSSL DEP_LIBZ CRYPTO_ONLY
             CDX_OUT SPDX_OUT COMPONENT_TYPE DOCUMENT_NAMESPACE
             LICENSE_OVERRIDE LICENSE_TEXT)
    set(_multi TARGETS DEFS DEP_VERSION INCLUDE_DIRS)
    cmake_parse_arguments(SB "${_opts}" "${_one}" "${_multi}" ${ARGN})

    if(NOT SB_NAME)
        message(FATAL_ERROR "wolfssl_compliance_tooling_add_sbom: NAME is required")
    endif()
    if(NOT SB_TARGETS AND NOT SB_LIB)
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

    set(_cmd ${CMAKE_COMMAND} -E env HOSTCC=${SB_HOSTCC}
             ${_WOLFSSL_COMPLIANCE_TOOLING_DRIVER}
             --name ${SB_NAME}
             --root ${SB_ROOT}
             --license-file ${SB_LICENSE}
             --hostcc ${SB_HOSTCC}
             --skip-missing)

    # Composition: a source set from the targets and/or a built library.
    if(SB_TARGETS)
        set(_srcs_file ${CMAKE_CURRENT_BINARY_DIR}/${SB_NAME}-sbom-srcs.txt)
        string(REPLACE ";" "\n" _srcs_nl "${_srcs}")
        file(GENERATE OUTPUT ${_srcs_file} CONTENT "${_srcs_nl}\n")
        list(APPEND _cmd --srcs-file ${_srcs_file})
    endif()
    if(SB_LIB)
        list(APPEND _cmd --lib ${SB_LIB})
    endif()
    if(SB_NO_ARTIFACT_HASH)
        list(APPEND _cmd --no-artifact-hash)
    endif()

    # Config: user_settings, a pre-expanded header, source-only, or -D flags.
    if(SB_USER_SETTINGS)
        list(APPEND _cmd --user-settings ${SB_USER_SETTINGS})
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
        list(APPEND _cmd --version ${SB_VERSION})
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
    if(SB_LICENSE_OVERRIDE)
        list(APPEND _cmd --license-override ${SB_LICENSE_OVERRIDE})
    endif()
    if(SB_LICENSE_TEXT)
        list(APPEND _cmd --license-text ${SB_LICENSE_TEXT})
    endif()
    if(SB_DOCUMENT_NAMESPACE)
        list(APPEND _cmd --document-namespace ${SB_DOCUMENT_NAMESPACE})
    endif()
    if(SB_DEP_WOLFSSL)
        list(APPEND _cmd --dep-wolfssl ${SB_DEP_WOLFSSL})
    endif()
    if(SB_DEP_WOLFCRYPT)
        list(APPEND _cmd --dep-wolfcrypt ${SB_DEP_WOLFCRYPT})
    endif()
    if(SB_DEP_OPENSSL)
        list(APPEND _cmd --dep-openssl ${SB_DEP_OPENSSL})
    endif()
    if(SB_DEP_LIBZ)
        list(APPEND _cmd --dep-libz ${SB_DEP_LIBZ})
    endif()
    if(SB_CRYPTO_ONLY)
        list(APPEND _cmd --crypto-only ${SB_CRYPTO_ONLY})
    endif()
    foreach(_dv IN LISTS SB_DEP_VERSION)
        list(APPEND _cmd --dep-version ${_dv})
    endforeach()
    if(SB_SBOM_GEN)
        list(APPEND _cmd --gen-sbom ${SB_SBOM_GEN})
    endif()
    if(SB_CDX_OUT)
        list(APPEND _cmd --cdx-out ${SB_CDX_OUT})
    endif()
    if(SB_SPDX_OUT)
        list(APPEND _cmd --spdx-out ${SB_SPDX_OUT})
    endif()

    add_custom_target(${SB_TARGET_NAME}
        COMMAND ${_cmd}
        WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
        VERBATIM
        COMMENT "Generating ${SB_NAME} SBOM (CycloneDX 1.6 + SPDX 2.3)")
endfunction()
