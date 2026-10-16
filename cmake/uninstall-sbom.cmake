# cmake -P script: uninstall wolfSSL SBOM artifacts.
# Invoked by the uninstall-sbom custom target.  Reads DESTDIR from the
# environment at script-execution time (build time).
#
# Required -D arguments (passed by add_custom_target in CMakeLists.txt):
#   WOLFSSL_VERSION         project version string
#   WOLFSSL_INSTALL_DOCDIR  resolved install doc directory (absolute)

foreach(_var WOLFSSL_VERSION WOLFSSL_INSTALL_DOCDIR)
    if(NOT DEFINED ${_var})
        message(FATAL_ERROR "uninstall-sbom.cmake: required variable ${_var} not set")
    endif()
endforeach()

if(DEFINED ENV{DESTDIR})
    set(_destdir "$ENV{DESTDIR}")
else()
    set(_destdir "")
endif()

set(_dest "${_destdir}${WOLFSSL_INSTALL_DOCDIR}")

# file(REMOVE ...) is a no-op for absent files, matching autotools `rm -f`.
file(REMOVE
    "${_dest}/wolfssl-${WOLFSSL_VERSION}.cdx.json"
    "${_dest}/wolfssl-${WOLFSSL_VERSION}.spdx.json"
    "${_dest}/wolfssl-${WOLFSSL_VERSION}.spdx")

message(STATUS "Uninstalled wolfSSL SBOM from ${_dest}")
