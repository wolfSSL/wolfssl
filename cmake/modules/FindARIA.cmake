# Filename: FindARIA.cmake
#
# Usage:
#   find_package(ARIA [REQUIRED] [QUIET])
#
# Once complete this will define:
#   ARIA_FOUND       - system has ARIA MagicCrypto
#   ARIA_INCLUDE_DIR - the include directory containing ARIA
#   ARIA_LIBRARY     - the path to the libARIA library
#   ARIA_IS_LOCAL    - optionally indicate the MagicCrypto is found locally in ./MagicCrypto

set(ARIA_INCLUDE_DIR)
set(ARIA_LIB_FILE)
set(ARIA_IS_LOCAL)

# when debugging cmake, ARIA_DIR environment variable can be manually set here:
# set(ENV{ARIA_DIR} "~/MagicCrypto")
# set(ENV{ARIA_DIR} "/mnt/c/workspace/MagicCrypto")
# set(ENV{ARIA_DIR} "c:\\workspace\\MagicCrypto")

# Make sure we have a ARIA_DIR environment variable with the path to MagicCrypto
if ("$ENV{ARIA_DIR}" STREQUAL "")
    message(STATUS "The ARIA_DIR environment variable is not defined. Looking for headers in wolfssl/MagicCrypto")
    if (EXISTS "${WOLFSSL_ROOT}/MagicCrypto/")
        set(ARIA_INCLUDE_DIR "${WOLFSSL_ROOT}/MagicCrypto/include")
        message(STATUS "Found ARIA in local MagicCrypto directory ${ARIA_INCLUDE_DIR}")
        set(ARIA_IS_LOCAL 1)
    else()
        message(ERROR "ERROR: FindARIA.cmake missing ARIA_DIR value")
        message(STATUS "Please set ARIA_DIR environment variable path to your MagicCrypto or copy to wolfssl/MagicCrypto")
    endif()
else()
    # If an environment variable is defined, the library CANNOT be in the local wolfssl directory.
    # See CMake documentation for target_include_directories()
    set(ARIA_IS_LOCAL)
    set(ARIA_INCLUDE_DIR "$ENV{ARIA_DIR}/include")
    message(STATUS "FindARIA.cmake found ARIA_INCLUDE_DIR = $ENV{ARIA_DIR}")

    message(STATUS "Checking environment location: ${ARIA_INCLUDE_DIR} and wolfSSL: ${WOLFSSL_ROOT}")
    get_filename_component(dir1 "${ARIA_INCLUDE_DIR}" REALPATH)
    get_filename_component(dir2 "${WOLFSSL_ROOT}/MagicCrypto/include" REALPATH)
    message(STATUS "Found location dir: ${dir1} and ${dir2}")
    if("${dir1}" STREQUAL "${dir2}")
        message(STATUS "${ARIA_INCLUDE_DIR} exists within ${WOLFSSL_ROOT}.")
        message(STATUS "Setting ARIA_IS_LOCAL flag and using wolfSSL path.")
        set(ARIA_IS_LOCAL 1)
        set(ARIA_INCLUDE_DIR "${WOLFSSL_ROOT}/MagicCrypto/include")
    else()
        if(EXISTS "${ARIA_INCLUDE_DIR}")
            message(STATUS "Confirmed directory exists: ${ARIA_INCLUDE_DIR}")
        else()
            message(FATAL_ERROR "Directory not found: ${ARIA_INCLUDE_DIR}")
        endif()

        message(STATUS "Confirmed ${ARIA_INCLUDE_DIR} is not in local wolfSSL root.")
    endif()
endif()

# Check that the appropriate files exist
find_path(ARIA_INCLUDE_DIR NAMES "mcapi.h" )

if (NOT EXISTS "${ARIA_INCLUDE_DIR}/mcapi.h")
    message(FATAL_ERROR "File does not exist at ${ARIA_INCLUDE_DIR}/mcapi.h")
endif()

if(NOT EXISTS "${ARIA_INCLUDE_DIR}/mcapi_error.h")
    message(FATAL_ERROR "File does not exist at ${ARIA_INCLUDE_DIR}/mcapi_error.h")
endif()

if(NOT EXISTS "${ARIA_INCLUDE_DIR}/mcapi_type.h")
    message(FATAL_ERROR "File does not exist at $ARIA_INCLUDE_DIR/mcapi_type.h")
endif()

if(EXISTS "$ENV{ARIA_DIR}/lib/libMagicCrypto.so")
    # Found ARIA binary via environment variable
    set(ARIA_LIBRARY "MagicCrypto")
    set(ARIA_LIB_FILE "$ENV{ARIA_DIR}/lib/libMagicCrypto.so")
    message(STATUS "ARIA Check: found libMagicCrypto.so via environment variable.")
    message(STATUS "Using ${ARIA_LIB_FILE}")
else()
    # Did not find ARIA binary via environment variable, so let's look in the current wolfssl directory
    if(EXISTS "${WOLFSSL_ROOT}/MagicCrypto/lib/libMagicCrypto.so")
        # Found in the root of wolfssl, in ./MagicCrypto/lib
        set(ARIA_LIBRARY "MagicCrypto")
        set(ARIA_LIB_FILE "${WOLFSSL_ROOT}/MagicCrypto/lib/libMagicCrypto.so")
        message(STATUS "ARIA Check: found libMagicCrypto.so via WOLFSSL_ROOT")
        message(STATUS "Using ${ARIA_LIB_FILE}")
    else()
        # Could not find binary. Give up.
        message(ERROR "ARIA Check: could not find libMagicCrypto.so via WOLFSSL_ROOT\n"
                      "Looked for ${WOLFSSL_ROOT}/MagicCrypto/lib/libMagicCrypto.so")
    endif()
endif()

mark_as_advanced(ARIA_INCLUDE_DIR ARIA_LIBRARY)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ARIA DEFAULT_MSG ARIA_INCLUDE_DIR ARIA_LIBRARY)

# Some additional optional debugging messages, set to (1) to enable
if(0)
    message(STATUS "")
    message(STATUS "ARIA Check: FindARIA.cmake")
    message(STATUS "ARIA Check: ARIA_INCLUDE_DIR: ${ARIA_INCLUDE_DIR}")
    message(STATUS "ARIA Check: ARIA_LIBRARY:     ${ARIA_LIBRARY}")
    message(STATUS "ARIA Check: ARIA_FOUND:       ${ARIA_FOUND}")
    message(STATUS "ARIA Check: CMAKE_CURRENT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}")
endif()
