# Filename: FindARIA.cmake
#
# Usage:
#   find_package(ARIA [REQUIRED] [QUIET])
#
# Once done this will define:
#   ARIA_FOUND       - system has ARIA MAgicCrypt0
#   ARIA_INCLUDE_DIR - the include directory containing ARIA
#   ARIA_LIBRARY     - the path to the libARIA library
#

set(ARIA_INCLUDE_DIR)
set(ARIA_LIB_FILE)

# when debugging cmake, ARIA_DIR environment variable can be manually set here:
# set(ENV{ARIA_DIR} "/mnt/c/workspace/MagicCrypto")
# set(ENV{ARIA_DIR} "c:\\workspace\\MagicCrypto")

# Make sure we have a ARIA_DIR encironment variable with the path to MagicCrypto
if ("$ENV{ARIA_DIR}" STREQUAL "")
    message(ERROR "ERROR: FindARIA.cmake missing ARIA_DIR value")
    message(STATUS "Please set ARIA_DIR environment variable path to your MagicCrypto")
else()
    set(ARIA_INCLUDE_DIR "$ENV{ARIA_DIR}/include")
    message(STATUS "FindARIA.cmake found ARIA_INCLUDE_DIR = $ENV{ARIA_DIR}")
    # set(ARIA_LIBRARY "$ENV{ARIA_INCLUDE_DIR}/lib")
endif()

# Check that the appropriate files exist
find_path(ARIA_INCLUDE_DIR NAMES "mcapi.h" )

if (EXISTS "${ARIA_INCLUDE_DIR}/mcapi.h")
    # message("Found ${ARIA_INCLUDE_DIR}/mcapi.h")
else()
    message(ERROR "File does not exist at ${ARIA_INCLUDE_DIR}/mcapi.h")
endif()

if(EXISTS "${ARIA_INCLUDE_DIR}/mcapi_error.h")
    # message("Found ${ARIA_INCLUDE_DIR}/mcapi_error.h")
else()
    message(ERROR "File does not exist at ${ARIA_INCLUDE_DIR}/mcapi_error.h")
endif()

if(EXISTS "${ARIA_INCLUDE_DIR}/mcapi_type.h")
    # message("Found ${ARIA_INCLUDE_DIR}/mcapi_type.h")
else()
    message(ERROR "File does not exist at $ARIA_INCLUDE_DIR/mcapi_type.h")
endif()

# find_library(ARIA_LIBRARY
#             NAMES "libMagicCrypto.so" # this is not the library name, nor is it "MagicCrypto"
#             HINTS "$ENV{ARIA_DIR}/lib/libMagicCrypto.so")

if(EXISTS "$ENV{ARIA_DIR}/lib/libMagicCrypto.so")
    set(ARIA_LIBRARY "MagicCrypto")
    set(ARIA_LIB_FILE "$ENV{ARIA_DIR}/lib/libMagicCrypto.so")
    # message(STATUS "ARIA Check: found libMagicCrypto.so via file exists")
endif()

mark_as_advanced(ARIA_INCLUDE_DIR ARIA_LIBRARY)

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(ARIA DEFAULT_MSG ARIA_INCLUDE_DIR ARIA_LIBRARY)

# message(STATUS "")
# message(STATUS "ARIA Check: FindARIA.cmake")
# message(STATUS "ARIA Check: ARIA_INCLUDE_DIR: ${ARIA_INCLUDE_DIR}")
# message(STATUS "ARIA Check: ARIA_LIBRARY:     ${ARIA_LIBRARY}")
# message(STATUS "ARIA Check: ARIA_FOUND:       ${ARIA_FOUND}")
# message(STATUS "ARIA Check: CMAKE_CURRENT_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR}")
