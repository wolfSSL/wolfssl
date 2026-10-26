# cmake -P script: install SBOM artifacts.
# DESTDIR is read from the environment when this script runs, so
# DESTDIR=/staging cmake --build . --target install-sbom stages the files.
#
# The CycloneDX and SPDX JSON files must exist. The tag-value file is
# copied only when the caller set its path and the file exists.

if(NOT DEFINED WOLFSSL_COMPLIANCE_TOOLING_INSTALL_DIR OR WOLFSSL_COMPLIANCE_TOOLING_INSTALL_DIR STREQUAL "")
    message(FATAL_ERROR "install-sbom.cmake: WOLFSSL_COMPLIANCE_TOOLING_INSTALL_DIR is required")
endif()

include("${CMAKE_CURRENT_LIST_DIR}/sbom-paths.cmake")
wolfssl_compliance_tooling_sbom_resolve_outputs(_cdx _spdx _tv)

# file(INSTALL) applies DESTDIR itself. Prepending it here would stage
# the files twice. file(MAKE_DIRECTORY) does not apply DESTDIR, so the
# directory is created at the staged path.
if(DEFINED ENV{DESTDIR})
    set(_destdir "$ENV{DESTDIR}")
else()
    set(_destdir "")
endif()
set(_staged "${_destdir}${WOLFSSL_COMPLIANCE_TOOLING_INSTALL_DIR}")

if(NOT EXISTS "${_cdx}")
    message(FATAL_ERROR "install-sbom.cmake: missing CycloneDX file ${_cdx}")
endif()
if(NOT EXISTS "${_spdx}")
    message(FATAL_ERROR "install-sbom.cmake: missing SPDX file ${_spdx}")
endif()

file(MAKE_DIRECTORY "${_staged}")
file(INSTALL "${_cdx}" "${_spdx}" DESTINATION "${WOLFSSL_COMPLIANCE_TOOLING_INSTALL_DIR}")
if(NOT _tv STREQUAL "" AND EXISTS "${_tv}")
    file(INSTALL "${_tv}" DESTINATION "${WOLFSSL_COMPLIANCE_TOOLING_INSTALL_DIR}")
endif()

message(STATUS "Installed SBOM to ${_staged}")
