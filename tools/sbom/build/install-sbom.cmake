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

# file(INSTALL) applies DESTDIR itself, and creates the directory. _staged
# is only for the message. On Windows, file(INSTALL) drops a drive letter
# before it adds DESTDIR, so D:/stage + C:/x is D:/stage/x;
# uninstall-sbom.cmake uses the same rule.
if(DEFINED ENV{DESTDIR})
    # Forward slashes, as file(INSTALL) prints them, so the message matches
    # the path it wrote on Windows too.
    file(TO_CMAKE_PATH "$ENV{DESTDIR}" _destdir)
else()
    set(_destdir "")
endif()
set(_install_dir "${WOLFSSL_COMPLIANCE_TOOLING_INSTALL_DIR}")
if(CMAKE_HOST_WIN32 AND NOT _destdir STREQUAL "")
    string(REGEX REPLACE "^[A-Za-z]:" "" _install_dir "${_install_dir}")
endif()
set(_staged "${_destdir}${_install_dir}")

if(NOT EXISTS "${_cdx}")
    message(FATAL_ERROR "install-sbom.cmake: missing CycloneDX file ${_cdx}")
endif()
if(NOT EXISTS "${_spdx}")
    message(FATAL_ERROR "install-sbom.cmake: missing SPDX file ${_spdx}")
endif()

file(INSTALL "${_cdx}" "${_spdx}" DESTINATION "${WOLFSSL_COMPLIANCE_TOOLING_INSTALL_DIR}")
if(NOT _tv STREQUAL "" AND EXISTS "${_tv}")
    file(INSTALL "${_tv}" DESTINATION "${WOLFSSL_COMPLIANCE_TOOLING_INSTALL_DIR}")
endif()

message(STATUS "Installed SBOM to ${_staged}")
