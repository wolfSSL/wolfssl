# cmake -P script: install wolfSSL SBOM artifacts.
# Invoked by the install-sbom custom target.  Reads DESTDIR from the
# environment at script-execution time (build time), so staging installs
# work correctly:
#
#   DESTDIR=/staging cmake --build <dir> --target install-sbom
#
# Required -D arguments (passed by add_custom_target in CMakeLists.txt):
#   WOLFSSL_SBOM_CDX        path to generated CycloneDX JSON
#   WOLFSSL_SBOM_SPDX       path to generated SPDX JSON
#   WOLFSSL_SBOM_TV         path to generated SPDX tag-value
#   WOLFSSL_VERSION         project version string
#   WOLFSSL_INSTALL_DOCDIR  resolved install doc directory (absolute)

foreach(_var WOLFSSL_SBOM_CDX WOLFSSL_SBOM_SPDX WOLFSSL_SBOM_TV
             WOLFSSL_VERSION WOLFSSL_INSTALL_DOCDIR)
    if(NOT DEFINED ${_var})
        message(FATAL_ERROR "install-sbom.cmake: required variable ${_var} not set")
    endif()
endforeach()

# DESTDIR is read from the environment at script-execution time so that
# `DESTDIR=/staging cmake --build . --target install-sbom` works the same
# way as `make install-sbom DESTDIR=/staging` with autotools.
if(DEFINED ENV{DESTDIR})
    set(_destdir "$ENV{DESTDIR}")
else()
    set(_destdir "")
endif()

set(_dest "${_destdir}${WOLFSSL_INSTALL_DOCDIR}")

file(MAKE_DIRECTORY "${_dest}")
file(COPY "${WOLFSSL_SBOM_CDX}"  DESTINATION "${_dest}")
file(COPY "${WOLFSSL_SBOM_SPDX}" DESTINATION "${_dest}")
file(COPY "${WOLFSSL_SBOM_TV}"   DESTINATION "${_dest}")

message(STATUS "Installed wolfSSL SBOM to ${_dest}")
