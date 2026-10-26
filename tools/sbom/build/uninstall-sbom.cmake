# cmake -P script: remove SBOM artifacts installed by install-sbom.cmake.
# DESTDIR is read from the environment when this script runs.
# file(REMOVE) does nothing when a file is already absent.

if(NOT DEFINED WOLFSSL_COMPLIANCE_TOOLING_INSTALL_DIR OR WOLFSSL_COMPLIANCE_TOOLING_INSTALL_DIR STREQUAL "")
    message(FATAL_ERROR "uninstall-sbom.cmake: WOLFSSL_COMPLIANCE_TOOLING_INSTALL_DIR is required")
endif()

include("${CMAKE_CURRENT_LIST_DIR}/sbom-paths.cmake")
wolfssl_compliance_tooling_sbom_resolve_outputs(_cdx _spdx _tv)

if(DEFINED ENV{DESTDIR})
    set(_destdir "$ENV{DESTDIR}")
else()
    set(_destdir "")
endif()
set(_dest "${_destdir}${WOLFSSL_COMPLIANCE_TOOLING_INSTALL_DIR}")

get_filename_component(_cdx_name "${_cdx}" NAME)
get_filename_component(_spdx_name "${_spdx}" NAME)
set(_remove
    "${_dest}/${_cdx_name}"
    "${_dest}/${_spdx_name}")
if(NOT _tv STREQUAL "")
    get_filename_component(_tv_name "${_tv}" NAME)
    list(APPEND _remove "${_dest}/${_tv_name}")
endif()

file(REMOVE ${_remove})
message(STATUS "Uninstalled SBOM from ${_dest}")
