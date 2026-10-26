# Shared path rules for install-sbom.cmake and uninstall-sbom.cmake.
# The names match the driver default: <bindir>/<name>-<version>.cdx.json
# and the .spdx.json sibling. A caller that set CDX_OUT / SPDX_OUT passes
# those paths and this file leaves them unchanged. The tag-value path is
# used only when the caller sets TV / TV_OUT. A .spdx sibling is not
# inferred, so a stale file is not installed or removed.

function(_wolfssl_compliance_tooling_read_version file macro out_var)
    set(_ver "")
    if(NOT file STREQUAL "" AND NOT macro STREQUAL "" AND EXISTS "${file}")
        file(STRINGS "${file}" _lines)
        foreach(_line IN LISTS _lines)
            if(_line MATCHES "${macro}[ \t]+\"([^\"]*)\"")
                set(_ver "${CMAKE_MATCH_1}")
                break()
            endif()
        endforeach()
    endif()
    set(${out_var} "${_ver}" PARENT_SCOPE)
endfunction()

function(wolfssl_compliance_tooling_sbom_resolve_outputs out_cdx out_spdx out_tv)
    if(NOT DEFINED WOLFSSL_COMPLIANCE_TOOLING_SBOM_CDX)
        set(WOLFSSL_COMPLIANCE_TOOLING_SBOM_CDX "")
    endif()
    if(NOT DEFINED WOLFSSL_COMPLIANCE_TOOLING_SBOM_SPDX)
        set(WOLFSSL_COMPLIANCE_TOOLING_SBOM_SPDX "")
    endif()
    if(NOT DEFINED WOLFSSL_COMPLIANCE_TOOLING_SBOM_TV)
        set(WOLFSSL_COMPLIANCE_TOOLING_SBOM_TV "")
    endif()
    if(NOT DEFINED WOLFSSL_COMPLIANCE_TOOLING_SBOM_NAME)
        set(WOLFSSL_COMPLIANCE_TOOLING_SBOM_NAME "")
    endif()
    if(NOT DEFINED WOLFSSL_COMPLIANCE_TOOLING_SBOM_VERSION)
        set(WOLFSSL_COMPLIANCE_TOOLING_SBOM_VERSION "")
    endif()
    if(NOT DEFINED WOLFSSL_COMPLIANCE_TOOLING_SBOM_VERSION_FILE)
        set(WOLFSSL_COMPLIANCE_TOOLING_SBOM_VERSION_FILE "")
    endif()
    if(NOT DEFINED WOLFSSL_COMPLIANCE_TOOLING_SBOM_VERSION_MACRO)
        set(WOLFSSL_COMPLIANCE_TOOLING_SBOM_VERSION_MACRO "")
    endif()
    if(NOT DEFINED WOLFSSL_COMPLIANCE_TOOLING_SBOM_BINDIR)
        set(WOLFSSL_COMPLIANCE_TOOLING_SBOM_BINDIR "")
    endif()

    set(_cdx "${WOLFSSL_COMPLIANCE_TOOLING_SBOM_CDX}")
    set(_spdx "${WOLFSSL_COMPLIANCE_TOOLING_SBOM_SPDX}")
    set(_tv "${WOLFSSL_COMPLIANCE_TOOLING_SBOM_TV}")

    if(_cdx STREQUAL "" OR _spdx STREQUAL "")
        set(_ver "${WOLFSSL_COMPLIANCE_TOOLING_SBOM_VERSION}")
        if(_ver STREQUAL "")
            _wolfssl_compliance_tooling_read_version(
                "${WOLFSSL_COMPLIANCE_TOOLING_SBOM_VERSION_FILE}"
                "${WOLFSSL_COMPLIANCE_TOOLING_SBOM_VERSION_MACRO}"
                _ver)
        endif()
        if(WOLFSSL_COMPLIANCE_TOOLING_SBOM_NAME STREQUAL "" OR _ver STREQUAL ""
           OR WOLFSSL_COMPLIANCE_TOOLING_SBOM_BINDIR STREQUAL "")
            message(FATAL_ERROR
                "sbom paths: pass CDX and SPDX, or NAME, BINDIR, and VERSION "
                "(or VERSION_FILE and VERSION_MACRO)")
        endif()
        if(_cdx STREQUAL "")
            set(_cdx "${WOLFSSL_COMPLIANCE_TOOLING_SBOM_BINDIR}/${WOLFSSL_COMPLIANCE_TOOLING_SBOM_NAME}-${_ver}.cdx.json")
        endif()
        if(_spdx STREQUAL "")
            set(_spdx "${WOLFSSL_COMPLIANCE_TOOLING_SBOM_BINDIR}/${WOLFSSL_COMPLIANCE_TOOLING_SBOM_NAME}-${_ver}.spdx.json")
        endif()
    endif()

    set(${out_cdx} "${_cdx}" PARENT_SCOPE)
    set(${out_spdx} "${_spdx}" PARENT_SCOPE)
    set(${out_tv} "${_tv}" PARENT_SCOPE)
endfunction()
