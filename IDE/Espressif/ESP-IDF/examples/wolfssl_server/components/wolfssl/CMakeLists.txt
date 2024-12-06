#
# Copyright (C) 2006-2024 wolfSSL Inc.
#
# This file is part of wolfSSL.
#
# wolfSSL is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# wolfSSL is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1335, USA
#
# cmake for wolfssl Espressif projects
#
# Version 5.7.2 Espressif ESP-IDF integration
#
# See https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/build-system.html
#
message(STATUS "Begin wolfssl ${CONFIG_CUSTOM_SETTING_WOLFSSL_ROOT}")
cmake_minimum_required(VERSION 3.16)

set(VERBOSE_COMPONENT_MESSAGES 1)

# Optional requires include:
# set(THIS_ESP_TLS "esp-tls")
set(THIS_ESP_TLS "")

# function: IS_ESP_IDF_COMPONENT
#  output:    RESULT = 1 (true) if this component is located in the ESP-IDF components
#             otherwise 0 (false)
function( IS_ESP_IDF_COMPONENT  RESULT )
    # NOTE: Component location is based on the location of the CMakeList.txt
    # and *not* the location of the wolfSSL source code. (which may be anywhere)

    # Normalize the paths to remove any trailing slashes
    get_filename_component(NORMALIZED_IDF_PATH  "${IDF_PATH}"      REALPATH)
    get_filename_component(NORMALIZED_TEST_PATH "${COMPONENT_DIR}" REALPATH)

    # Check if the test path starts with the IDF_PATH
    string(FIND "${NORMALIZED_TEST_PATH}" "${NORMALIZED_IDF_PATH}" pos)

    if(${pos} EQUAL 0)
        message(STATUS "${COMPONENT_DIR} is within IDF_PATH.")
        set(${RESULT} 1 PARENT_SCOPE)
    else()
        message(STATUS "${COMPONENT_DIR} is not within IDF_PATH.")
        set(${RESULT} 0 PARENT_SCOPE)
    endif()
endfunction()

# Determine if this cmake file is located in the ESP-IDF component directory or not,
# and if so, if it is being ignored (allowing the use of a local project one, instead).
IS_ESP_IDF_COMPONENT( IS_WOLSSL_ESP_IDF_COMPONENT )
if( IS_WOLSSL_ESP_IDF_COMPONENT )
    message(STATUS "This wolfSSL is a component in ESP-IDF.")
    if ( CONFIG_IGNORE_ESP_IDF_WOLFSSL_COMPONENT )
        idf_component_register()
        message(STATUS "Warning: wolfSSL component in ESP-IDF is being ignored.")
        return()
    endif()
endif()


if( "${CONFIG_CUSTOM_SETTING_WOLFSSL_ROOT}" STREQUAL "" )
    # nothing to do
else()
    # Only forward slashes, or double backslashes are supported.
    # By the time we get here the sdkconfig file has a value for wolfSSL source code root.
    string(REPLACE "\\" "/" CONFIG_CUSTOM_SETTING_WOLFSSL_ROOT ${CONFIG_CUSTOM_SETTING_WOLFSSL_ROOT})
    message(STATUS "Cleaned wolfssl path: ${CONFIG_CUSTOM_SETTING_WOLFSSL_ROOT}")
endif()

# The scope of this CMAKE_C_FLAGS is just this component:
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_USER_SETTINGS")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DWOLFSSL_USER_SETTINGS")

set(CMAKE_CURRENT_SOURCE_DIR ".")
# set(COMPONENT_REQUIRES lwip) # we typically don't need lwip directly in wolfssl component

# Optionally set your source to wolfSSL in your project CMakeLists.txt like this:
# set(WOLFSSL_ROOT "c:/test/my_wolfssl" )

if ( "${WOLFSSL_ROOT}" STREQUAL "")
    set(WOLFSSL_ROOT "$ENV{WOLFSSL_ROOT}" )
endif()

if(  "$ENV{IDF_PATH}" STREQUAL "" )
    message(FATAL_ERROR "IDF_PATH Environment variable not set!")
else()
    string(REPLACE "\\" "/" THIS_IDF_PATH "$ENV{IDF_PATH}")
endif()

# Optional compiler definitions to help with system name detection (typically printed by app diagnostics)
if(VERBOSE_COMPONENT_MESSAGES)
    if(WIN32)
        # Windows-specific configuration here
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_CMAKE_SYSTEM_NAME_WINDOWS")
        message(STATUS "Detected Windows")
    endif()
    if(CMAKE_HOST_UNIX)
        message(STATUS "Detected UNIX")
    endif()
    if(APPLE)
        message(STATUS "Detected APPLE")
    endif()
    if(CMAKE_HOST_UNIX AND (NOT APPLE) AND EXISTS "/proc/sys/fs/binfmt_misc/WSLInterop")
        # Windows-specific configuration here
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_CMAKE_SYSTEM_NAME_WSL")
        message(STATUS "Detected WSL")
    endif()
    if(CMAKE_HOST_UNIX AND (NOT APPLE) AND (NOT WIN32))
        # Windows-specific configuration here
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_CMAKE_SYSTEM_NAME_LINUX")
        message(STATUS "Detected Linux")
    endif()
    if(APPLE)
        # Windows-specific configuration here
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_CMAKE_SYSTEM_NAME_APPLE")
        message(STATUS "Detected Apple")
    endif()
endif() # End optional WOLFSSL_CMAKE_SYSTEM_NAME

message(STATUS "CONFIG_TARGET_PLATFORM = ${CONFIG_TARGET_PLATFORM}")

# Check that there are not conflicting wolfSSL components
# The ESP Registry Component will be in ./managed_components/wolfssl__wolfssl
# The local component wolfSSL directory will be in ./components/wolfssl
if( EXISTS "${CMAKE_HOME_DIRECTORY}/managed_components/wolfssl__wolfssl" AND EXISTS "${CMAKE_HOME_DIRECTORY}/components/wolfssl" )
    # These exclude statements don't seem to be honored by the $ENV{IDF_PATH}/tools/cmake/project.cmake'
    # add_subdirectory("${CMAKE_HOME_DIRECTORY}/managed_components/wolfssl__wolfssl" EXCLUDE_FROM_ALL)
    # add_subdirectory("${CMAKE_HOME_DIRECTORY}/managed_components/wolfssl__wolfssl/include" EXCLUDE_FROM_ALL)
    # So we'll error out and let the user decide how to proceed:
    message(WARNING "\nFound wolfSSL components in\n"
                    "./managed_components/wolfssl__wolfssl\n"
                    "and\n"
                    "./components/wolfssl\n"
                    "in project directory: \n"
                    "${CMAKE_HOME_DIRECTORY}")
    message(FATAL_ERROR "\nPlease use either the ESP Registry Managed Component or the wolfSSL component directory but not both.\n"
                        "If removing the ./managed_components/wolfssl__wolfssl directory, remember to also remove "
                        "or rename the idf_component.yml file typically found in ./main/")
else()
    message(STATUS "No conflicting wolfSSL components found.")
endif()


# Don't include lwip requirement for benchmark and test apps.
if( ("${CMAKE_PROJECT_NAME}" STREQUAL "wolfssl_benchmark") OR ("${CMAKE_PROJECT_NAME}" STREQUAL "wolfssl_test") )
    message(STATUS "Not including lwip for ${CMAKE_PROJECT_NAME}")
else()
    # benchmark and test do not need wifi, everything else probably does:
    set(COMPONENT_REQUIRES lwip "${THIS_ESP_TLS}") # we typically don't need lwip directly in wolfssl component
endif()

# find the user name to search for possible "wolfssl-username"
message(STATUS "USERNAME = $ENV{USERNAME}")
if(  "$ENV{USER}" STREQUAL "" ) # the bash user
    if(  "$ENV{USERNAME}" STREQUAL "" ) # the Windows user
        message(STATUS "could not find USER or USERNAME")
    else()
        # the bash user is not blank, so we'll use it.
        set(THIS_USER "$ENV{USERNAME}")
    endif()
else()
    # the bash user is not blank, so we'll use it.
    set(THIS_USER "$ENV{USER}")
endif()
message(STATUS "THIS_USER = ${THIS_USER}")

if( "$ENV{IDF_PATH}" STREQUAL "" )
    message(FATAL_ERROR "IDF_PATH Environment variable not set!")
else()
    string(REPLACE "\\" "/" THIS_IDF_PATH "$ENV{IDF_PATH}")
endif()

# ENVIRONMENT_VAR_TO_MACRO
# Check environment variable name EVARPARAM as [name]
# If defined, and has a value of EVARVALUE as [value],
# then assign a compiler definition "-D[name]=[value]"
function(ENVIRONMENT_VAR_TO_MACRO EVARPARAM EVARVALUE)
    # If the EVARPARAM environment variable name is set to EVARVALUE,
    # set the compiler flag definition to enable CSV output.
    if ( "$ENV{${EVARPARAM}}" STREQUAL "${EVARVALUE}")
        message(STATUS "Appending compile definition: -D${EVARPARAM}=${EVARVALUE}")
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -D${EVARPARAM}=${EVARVALUE}")
    else()
        if(DEFINED ENV{${EVARPARAM}})
            message(STATUS "Environment variable ${EVARPARAM} detected but set to $ENV{${EVARPARAM}}, not appending compile definition.")
        else()
            message(STATUS "Environment variable ${EVARPARAM} not detected, not appending compile definition.")
        endif()
    endif()
endfunction()

# COMPONENT_NAME = wolfssl
# The component name is the directory name. "No feature to change this".
# See https://github.com/espressif/esp-idf/issues/8978#issuecomment-1129892685

# set the root of wolfSSL in top-level project CMakelists.txt:
#   set(WOLFSSL_ROOT  "C:/some path/with/spaces")
#   set(WOLFSSL_ROOT  "c:/workspace/wolfssl-[username]")
#   set(WOLFSSL_ROOT  "/mnt/c/some path/with/spaces")
#   or use this logic to assign value from Environment Variable WOLFSSL_ROOT,
#   or assume this is an example 7 subdirectories below:

# We are typically in [root]/IDE/Espressif/ESP-IDF/examples/wolfssl_test/components/wolfssl
# The root of wolfSSL is 7 directories up from here:

# function: IS_WOLFSSL_SOURCE
#  parameter: DIRECTORY_PARAMETER - the directory to test
#  output:    RESULT = contains contents of DIRECTORY_PARAMETER for wolfssl directory, otherwise blank.
function( IS_WOLFSSL_SOURCE  DIRECTORY_PARAMETER
          RESULT )
    if (EXISTS "${DIRECTORY_PARAMETER}/wolfcrypt/src")
        set(${RESULT} "${DIRECTORY_PARAMETER}" PARENT_SCOPE)
    else()
        set(${RESULT} "" PARENT_SCOPE)
    endif()
endfunction()

# *********************************************************************************************
# function: FIND_WOLFSSL_DIRECTORY
#  parameter: OUTPUT_FOUND_WOLFSSL_DIRECTORY contains root of source code, otherwise blank
#
# Example usage:
#   FIND_WOLFSSL_DIRECTORY(WOLFSSL_ROOT)
# *********************************************************************************************
function(FIND_WOLFSSL_DIRECTORY OUTPUT_FOUND_WOLFSSL_DIRECTORY)
    message(STATUS "Starting FIND_WOLFSSL_DIRECTORY: ${${OUTPUT_FOUND_WOLFSSL_DIRECTORY}}")

    if ( "${${OUTPUT_FOUND_WOLFSSL_DIRECTORY}}" STREQUAL "" )
        # The parameter is empty, so we certainly need to search.
        # First, see if there's an environment variable. This takes highest priority (unless already found as hard-coded, above)
        set(CURRENT_SEARCH_DIR "$ENV{WOLFSSL_ROOT}")
        if( "${CURRENT_SEARCH_DIR}" STREQUAL "" )
            message(STATUS "The WOLFSSL_ROOT environment variable is not set. Searching...")
            # Next, if not found, see if wolfSSL was selected for ESP-TLS Kconfig
            if(CONFIG_CUSTOM_SETTING_WOLFSSL_ROOT)
                set(CURRENT_SEARCH_DIR ${CONFIG_CUSTOM_SETTING_WOLFSSL_ROOT})
                get_filename_component(CURRENT_SEARCH_DIR "${CURRENT_SEARCH_DIR}" ABSOLUTE)
                message(STATUS "WOLFSSL_ROOT found in sdkconfig/KConfig: ${CONFIG_CUSTOM_SETTING_WOLFSSL_ROOT}")
            else()
                message(STATUS "wolfSSL not defined in [Component Config] [wolfssl]. Continuing search...")
                # If not specified as a search hint in OUTPUT_FOUND_WOLFSSL_DIRECTORY:
                # This wolfSSL component CMakeLists.txt may be found EITHER in:
                #   1) local project component
                #   2) ESP-IDF share components
                # We'll start in the CMAKE_CURRENT_SOURCE_DIR, typically [something]/projectname/components/wolfssl
                # That option might find wolfSSL source code as a copy in the component directory (e.g. Managed Components)
                # Unless cmake is in the ESP-IDF, in which case it is unlikely to find wolfSSL source in any parent.
                message(STATUS "CMAKE_CURRENT_SOURCE_DIR = ${CMAKE_CURRENT_SOURCE_DIR}")
                get_filename_component(CURRENT_SEARCH_DIR "${CMAKE_CURRENT_SOURCE_DIR}" ABSOLUTE)
                message(STATUS "CURRENT_SEARCH_DIR = ${CURRENT_SEARCH_DIR}")
                string(LENGTH ${CURRENT_SEARCH_DIR} CURRENT_SEARCH_DIR_LENGTH)
            endif() # CONFIG_CUSTOM_SETTING_WOLFSSL_ROOT
        endif() # check environment var blank
    else()
        message(STATUS "Parameter found for FIND_WOLFSSL_DIRECTORY")
        message(STATUS "Setting wolfSSL search directory to: ${${OUTPUT_FOUND_WOLFSSL_DIRECTORY}}")
        set(CURRENT_SEARCH_DIR "${${OUTPUT_FOUND_WOLFSSL_DIRECTORY}}")
    endif() # parameter empty

    # Check to see if we found a path in environment or config settings, above.
    if( "${CURRENT_SEARCH_DIR}" STREQUAL "" )
        message(STATUS "Source for wolfSSL not specified in path nor config settings.")
        # We'll continue the search by recursing up the directory tree, below.
    else()
        # Setting found! Does it contain a valid path?
        string(REPLACE "\\" "/" CURRENT_SEARCH_DIR ${CURRENT_SEARCH_DIR})
        get_filename_component(CURRENT_SEARCH_DIR "${CURRENT_SEARCH_DIR}" ABSOLUTE)
        IS_WOLFSSL_SOURCE("${CURRENT_SEARCH_DIR}" FOUND_WOLFSSL)
        if( FOUND_WOLFSSL )
            message(STATUS "Found wolfSSL source code via setting: ${CURRENT_SEARCH_DIR}")
            set(${OUTPUT_FOUND_WOLFSSL_DIRECTORY} ${CURRENT_SEARCH_DIR} PARENT_SCOPE)
            return()
        else()
            if(WIN32)
                message(STATUS "When specifying a path for Windows, use forward slahes, or double backslashes.")
            endif()
            message(STATUS "CONFIG_CUSTOM_SETTING_WOLFSSL_ROOT sdkconfig setting = ${CONFIG_CUSTOM_SETTING_WOLFSSL_ROOT}")
            message(STATUS "WOLFSSL_ROOT Variable defined, but source code not found: ${CURRENT_SEARCH_DIR}")
        endif()
    endif()


    # we'll start in the CMAKE_CURRENT_SOURCE_DIR, typically [something]/projectname/components/wolfssl
    message(STATUS "CMAKE_CURRENT_SOURCE_DIR = ${CMAKE_CURRENT_SOURCE_DIR}")
    get_filename_component(CURRENT_SEARCH_DIR "${CMAKE_CURRENT_SOURCE_DIR}" ABSOLUTE)
    message(STATUS "CURRENT_SEARCH_DIR = ${CURRENT_SEARCH_DIR}")
    string(LENGTH ${CURRENT_SEARCH_DIR} CURRENT_SEARCH_DIR_LENGTH)

    # loop through all the parents, looking for wolfssl
    while(NOT CURRENT_SEARCH_DIR STREQUAL "/" AND NOT CURRENT_SEARCH_DIR STREQUAL "" )
        string(LENGTH ${CURRENT_SEARCH_DIR} CURRENT_SEARCH_DIR_LENGTH)
        # wolfSSL may simply be in a parent directory, such as for local examples in wolfssl repo
        IS_WOLFSSL_SOURCE("${CURRENT_SEARCH_DIR}" FOUND_WOLFSSL)
        if( FOUND_WOLFSSL )
            message(STATUS "Found wolfssl in CURRENT_SEARCH_DIR = ${CURRENT_SEARCH_DIR}")
            set(${OUTPUT_FOUND_WOLFSSL_DIRECTORY} ${CURRENT_SEARCH_DIR} PARENT_SCOPE)
            return()
        endif()

        # Maintain CURRENT_SEARCH_DIR, but check various suffixes with CURRENT_SEARCH_DIR_ALT
        if( THIS_USER )
            # Check for "wolfssl-[username]" subdirectory as we recurse up the directory tree
            set(CURRENT_SEARCH_DIR_ALT ${CURRENT_SEARCH_DIR}/wolfssl-${THIS_USER})
            message(STATUS "Looking in ${CURRENT_SEARCH_DIR_ALT}")

            IS_WOLFSSL_SOURCE("${CURRENT_SEARCH_DIR_ALT}" FOUND_WOLFSSL )
            if ( FOUND_WOLFSSL )
                message(STATUS "Found wolfssl in user-suffix CURRENT_SEARCH_DIR_ALT = ${CURRENT_SEARCH_DIR_ALT}")
                set(CURRENT_SEARCH_DIR "${CURRENT_SEARCH_DIR_ALT}")
                set(${OUTPUT_FOUND_WOLFSSL_DIRECTORY} ${CURRENT_SEARCH_DIR} PARENT_SCOPE)
                return()
            endif()
        endif()

        if ( FOUND_WOLFSSL )
            # if we already found the source, skip attempt of "wolfssl-master"
        else()
            set(CURRENT_SEARCH_DIR_ALT ${CURRENT_SEARCH_DIR}/wolfssl-master)
            message(STATUS "Looking in ${CURRENT_SEARCH_DIR_ALT}")

            IS_WOLFSSL_SOURCE("${CURRENT_SEARCH_DIR_ALT}" FOUND_WOLFSSL )
            if ( FOUND_WOLFSSL )
                message(STATUS "Found wolfssl in master-suffix CURRENT_SEARCH_DIR_ALT = ${CURRENT_SEARCH_DIR_ALT}")
                set(CURRENT_SEARCH_DIR "${CURRENT_SEARCH_DIR_ALT}")
                set(${OUTPUT_FOUND_WOLFSSL_DIRECTORY} ${CURRENT_SEARCH_DIR} PARENT_SCOPE)
                return()
            endif()
        endif()

        if ( FOUND_WOLFSSL )
            # if we already found the source, skip attempt of "wolfssl"
        else()
            set(CURRENT_SEARCH_DIR_ALT ${CURRENT_SEARCH_DIR}/wolfssl)
            message(STATUS "Looking in ${CURRENT_SEARCH_DIR_ALT}")

            IS_WOLFSSL_SOURCE("${CURRENT_SEARCH_DIR_ALT}" FOUND_WOLFSSL )
            if ( FOUND_WOLFSSL )
                message(STATUS "Found wolfssl in CURRENT_SEARCH_DIR_ALT = ${CURRENT_SEARCH_DIR_ALT}")
                set(CURRENT_SEARCH_DIR "${CURRENT_SEARCH_DIR_ALT}")
                set(${OUTPUT_FOUND_WOLFSSL_DIRECTORY} ${CURRENT_SEARCH_DIR} PARENT_SCOPE)
                return()
            endif()
        endif()

        # Next check for no user suffix "wolfssl" subdirectory as we recurse up the directory tree
        set(CURRENT_SEARCH_DIR_ALT ${CURRENT_SEARCH_DIR}/wolfssl)
        # if(EXISTS ${CURRENT_SEARCH_DIR} AND IS_DIRECTORY ${CURRENT_SEARCH_DIR} AND EXISTS "${CURRENT_SEARCH_DIR}/wolfcrypt/src")
        IS_WOLFSSL_SOURCE("${CURRENT_SEARCH_DIR_ALT}" FOUND_WOLFSSL )
        if ( FOUND_WOLFSSL )
            message(STATUS "Found wolfssl in CURRENT_SEARCH_DIR = ${CURRENT_SEARCH_DIR}")
            set(${OUTPUT_FOUND_WOLFSSL_DIRECTORY} ${CURRENT_SEARCH_DIR} PARENT_SCOPE)
            return()
        endif()

        # Move up one directory level
        set(PRIOR_SEARCH_DIR "${CURRENT_SEARCH_DIR}")
        get_filename_component(CURRENT_SEARCH_DIR "${CURRENT_SEARCH_DIR}" DIRECTORY)
        message(STATUS "Next CURRENT_SEARCH_DIR = ${CURRENT_SEARCH_DIR}")
        if( "${PRIOR_SEARCH_DIR}" STREQUAL "${CURRENT_SEARCH_DIR}" )
            # When the parent is current directory, cannot go any further. We didn't find wolfssl.
            # When the search directory is empty, we'll give up.
            set(CURRENT_SEARCH_DIR "")
        endif()
    endwhile()

    # If not found, set the output variable to empty before exiting
    set(${OUTPUT_FOUND_WOLFSSL_DIRECTORY} "" PARENT_SCOPE)
endfunction()


# Example usage:
#
# Simply find the WOLFSSL_DIRECTORY by searching parent directories:
#   FIND_WOLFSSL_DIRECTORY(WOLFSSL_ROOT)
#

message(STATUS "CONFIG_TARGET_PLATFORM = ${CONFIG_TARGET_PLATFORM}")

# Check for environment variable that may be assigned to macros
ENVIRONMENT_VAR_TO_MACRO("GENERATE_MACHINE_PARSEABLE_REPORT" "1")
ENVIRONMENT_VAR_TO_MACRO("WOLFSSL_BENCHMARK_FIXED_CSV"       "1")

# Optional variable inspection
if (0)
    get_cmake_property(_variableNames VARIABLES)
    list (SORT _variableNames)
    message(STATUS "")
    message(STATUS "ALL VARIABLES BEGIN")
    message(STATUS "")
    foreach (_variableName ${_variableNames})
        message(STATUS "${_variableName}=${${_variableName}}")
    endforeach()
    message(STATUS "")
    message(STATUS "ALL VARIABLES END")
    message(STATUS "")
endif()

if ( ("${CONFIG_TARGET_PLATFORM}" STREQUAL "esp8266") OR ("${IDF_TARGET}" STREQUAL "esp8266") )
    # There's no esp_timer, no driver components for the ESP8266
    message(STATUS "Early expansion EXCLUDES esp_timer for esp8266: ${THIS_INCLUDE_TIMER}")
    message(STATUS "Early expansion EXCLUDES driver for esp8266: ${THIS_INCLUDE_DRIVER}")
    set(THIS_INCLUDE_TIMER "")
    set(THIS_INCLUDE_DRIVER "")
    set(THIS_ESP_TLS "")
else()
    message(STATUS "Early expansion includes esp_timer: ${THIS_INCLUDE_TIMER}")
    message(STATUS "Early expansion includes driver: ${THIS_INCLUDE_DRIVER}")
    set(THIS_INCLUDE_TIMER "esp_timer")
    set(THIS_INCLUDE_DRIVER "driver")
    set(THIS_ESP_TLS "esp-tls")
    # Let the app know that we've included the esp-tls component requirement.
    # This is critical for use the the esp-tls component. See wolfssl esp_crt_bundle.c file.
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_CMAKE_REQUIRED_ESP_TLS=1")
endif()

if(CMAKE_BUILD_EARLY_EXPANSION)
    message(STATUS "wolfssl component CMAKE_BUILD_EARLY_EXPANSION:")
    idf_component_register(
                            REQUIRES "${COMPONENT_REQUIRES}"
                            PRIV_REQUIRES # esp_hw_support
                                          "${THIS_ESP_TLS}"
                                          "${THIS_INCLUDE_TIMER}"
                                          "${THIS_INCLUDE_DRIVER}" # this will typically only be needed for wolfSSL benchmark
                           )

else()
    # not CMAKE_BUILD_EARLY_EXPANSION
    message(STATUS "************************************************************************************************")
    message(STATUS "wolfssl component config:")
    message(STATUS "************************************************************************************************")

    if ( "${CONFIG_TARGET_PLATFORM}" STREQUAL "esp8266")
        # There's no esp_timer, no driver components for the ESP8266
        set(THIS_INCLUDE_TIMER "")
        set(THIS_INCLUDE_DRIVER "")
    else()
        set(THIS_INCLUDE_TIMER "esp_timer")
        set(THIS_INCLUDE_DRIVER "driver")
    endif()

    # search for wolfSSL
    FIND_WOLFSSL_DIRECTORY(WOLFSSL_ROOT)
    if(WOLFSSL_ROOT)
        IS_WOLFSSL_SOURCE("${WOLFSSL_ROOT}" FOUND_WOLFSSL)
        if(FOUND_WOLFSSL)
            message(STATUS "Found WOLFSSL_ROOT via CMake specification.")
        else()
            # WOLFSSL_ROOT Path specified in CMakeLists.txt is not a valid path
            message(FATAL_ERROR "WOLFSSL_ROOT CMake Variable defined, but path not found: ${WOLFSSL_ROOT}\n"
                                "Try correcting WOLFSSL_ROOT in your project CMakeFile.txt or setting environment variable.")
            # Abort CMake after fatal error.
        endif()
    else()
        message(STATUS "Source code for wolfSSL still not found.")
        message(STATUS "Searching from project home: ${CMAKE_HOME_DIRECTORY} ...")
        set(WOLFSSL_ROOT "${CMAKE_HOME_DIRECTORY}")
        FIND_WOLFSSL_DIRECTORY(WOLFSSL_ROOT)
    endif()


    if(WOLFSSL_ROOT)
        message(STATUS "Confirmed wolfssl directory at: ${WOLFSSL_ROOT}")
    else()
        # Try to allow a more intuitive error that the source code was not found in cmake:
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_CMAKE_WARNING_SOURCE_NOT_FOUND")

        message(STATUS "Failed: wolfssl source code directory not found.")
        # Abort. We need wolfssl _somewhere_.
        message(STATUS "")
        message(STATUS "")
        message(STATUS "Could not find wolfssl in any parent directory named wolfssl-${THIS_USER}, wolfssl-master, or wolfssl.\n"
                       "Try setting WOLFSSL_ROOT environment variable, cmake variable in project, copy source, or use managed components.")
        message(STATUS "")
        message(STATUS "")
        # Abort CMake after fatal error. (or not?)
    endif()

    set(INCLUDE_PATH ${WOLFSSL_ROOT})

    set(WOLFSSL_EXTRA_PROJECT_DIR "${WOLFSSL_ROOT}/src/")

    # During regression tests, optionally copy source locally and use: set(USE_LOCAL_TEST_BENCH 1)
    set(USE_LOCAL_TEST_BENCH 0)
    if(NOT USE_LOCAL_TEST_BENCH)
        if( "${CMAKE_PROJECT_NAME}" STREQUAL "hello-world" )
            message(STATUS "Include ${WOLFSSL_ROOT}/wolfcrypt/benchmark")
            set(WOLFSSL_EXTRA_PROJECT_DIR "${WOLFSSL_ROOT}/wolfcrypt/benchmark")
        endif()

        if( "${CMAKE_PROJECT_NAME}" STREQUAL "wolfssl_benchmark" )
            message(STATUS "Include ${WOLFSSL_ROOT}/wolfcrypt/benchmark")
            set(WOLFSSL_EXTRA_PROJECT_DIR "${WOLFSSL_ROOT}/wolfcrypt/benchmark")
        endif()

        if( "${CMAKE_PROJECT_NAME}" STREQUAL "wolfssl_test" )
            message(STATUS "Include ${WOLFSSL_ROOT}/wolfcrypt/test")
            set(WOLFSSL_EXTRA_PROJECT_DIR "${WOLFSSL_ROOT}/wolfcrypt/test")
        endif()
    endif()

    message(STATUS "WOLFSSL_EXTRA_PROJECT_DIR = ${WOLFSSL_EXTRA_PROJECT_DIR}")
    set(COMPONENT_SRCDIRS "\"${WOLFSSL_ROOT}/src/\""
                          "\"${WOLFSSL_ROOT}/wolfcrypt/src\""
                          "\"${WOLFSSL_ROOT}/wolfcrypt/src/port/Espressif\""
                          "\"${WOLFSSL_ROOT}/wolfcrypt/src/port/Espressif/esp_crt_bundle\""
                          "\"${WOLFSSL_ROOT}/wolfcrypt/src/port/atmel\""
                          "\"${WOLFSSL_EXTRA_PROJECT_DIR}\""
                         ) # COMPONENT_SRCDIRS

    message(STATUS "This COMPONENT_SRCDIRS = ${COMPONENT_SRCDIRS}")

    # wolfSSL user_settings.h may be in the local project.
    # TODO check if exists and possibly set to ESP-IDF
    set(WOLFSSL_PROJECT_DIR "${CMAKE_HOME_DIRECTORY}/components/wolfssl")

    string(REPLACE "/" "//" STR_WOLFSSL_PROJECT_DIR "${WOLFSSL_PROJECT_DIR}")
    add_compile_definitions(WOLFSSL_USER_SETTINGS_DIR="${STR_WOLFSSL_PROJECT_DIR}/include/user_settings.h")
    message(STATUS "Added definition for user_settings.h: -DWOLFSSL_USER_SETTINGS_DIR=\"${STR_WOLFSSL_PROJECT_DIR}//include//user_settings.h\"")
    # Espressif may take several passes through this makefile. Check to see if we found IDF
    string(COMPARE EQUAL "${PROJECT_SOURCE_DIR}" "" WOLFSSL_FOUND_IDF)

    # get a list of all wolfcrypt assembly files; we'll exclude them as they don't target Xtensa
    file(GLOB EXCLUDE_ASM *.S)
    file(GLOB EXCLUDE_ASM ${CMAKE_SOURCE_DIR} "${WOLFSSL_ROOT}/wolfcrypt/src/*.S")

    message(STATUS "IDF_PATH = $ENV{IDF_PATH}")
    message(STATUS "PROJECT_SOURCE_DIR = ${PROJECT_SOURCE_DIR}")
    message(STATUS "EXCLUDE_ASM = ${EXCLUDE_ASM}")

    #
    # Check to see if there's both a local copy and EDP-IDF copy of the wolfssl and/or wolfssh components.
    #
    if( EXISTS "${WOLFSSL_PROJECT_DIR}" AND EXISTS "$ENV{IDF_PATH}/components/wolfssl/" )
        #
        # wolfSSL found in both ESP-IDF and local project - needs to be resolved by user
        #
        message(STATUS "")
        message(STATUS "**************************************************************************************")
        message(STATUS "")
        message(STATUS "Error: Found components/wolfssl in both local project and IDF_PATH")
        message(STATUS "")
        message(STATUS "To proceed: ")
        message(STATUS "")
        message(STATUS "Remove either the local project component: ${WOLFSSL_PROJECT_DIR} ")
        message(STATUS "or the Espressif shared component installed at: $ENV{IDF_PATH}/components/wolfssl/ ")
        message(STATUS "")
        message(STATUS "")
        message(STATUS "**************************************************************************************")
        message(STATUS "")

        message(STATUS "Please use wolfSSL in either local project or Espressif components, but not both.")

        # Optional: if you change the above FATAL_ERROR to STATUS you can warn at runtime with this macro definition:
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_MULTI_INSTALL_WARNING")

    else()
        if( EXISTS "$ENV{IDF_PATH}/components/wolfssl/" )
            #
            # wolfSSL found in ESP-IDF components and is assumed to be already configured in user_settings.h via setup.
            #
            message(STATUS "")
            message(STATUS "Using components/wolfssl in IDF_PATH = $ENV{IDF_PATH}")
            message(STATUS "")
        else()
            #
            # wolfSSL is not an ESP-IDF component.
            # We need to now determine if it is local and if so if it is part of the wolfSSL repo,
            # or if  wolfSSL is simply installed as a local component.
            #

            if( EXISTS "${WOLFSSL_PROJECT_DIR}" )
                #
                # wolfSSL found in local project.
                #
                if( EXISTS "${WOLFSSL_PROJECT_DIR}/wolfcrypt/" )
                    message(STATUS "")
                    message(STATUS "Using installed project ./components/wolfssl in CMAKE_HOME_DIRECTORY = ${CMAKE_HOME_DIRECTORY}")
                    message(STATUS "")
                    #
                    # Note we already checked above and confirmed there's not another wolfSSL installed in the ESP-IDF components.
                    #
                    # We won't do anything else here, as it will be assumed the original install completed successfully.
                    #
                else() # full wolfSSL not installed in local project
                    #
                    # This is the developer repo mode. wolfSSL will be assumed to be not installed to ESP-IDF nor local project
                    # In this configuration, we are likely running a wolfSSL example found directly in the repo.
                    #
                    message(STATUS "")
                    message(STATUS "Using developer repo ./components/wolfssl in CMAKE_HOME_DIRECTORY = ${CMAKE_HOME_DIRECTORY}")
                    message(STATUS "")

                    message(STATUS "************************************************************************************************")
                    # When in developer mode, we are typically running wolfSSL examples such as benchmark or test directories.
                    # However, the as-cloned or distributed wolfSSL does not have the ./include/ directory, so we'll add it as needed.
                    #
                    # first check if there's a [root]/include/user_settings.h
                    if( EXISTS "${WOLFSSL_ROOT}/include/user_settings.h" )
                        message(FATAL_ERROR "Found stray wolfSSL user_settings.h in "
                                            "${WOLFSSL_ROOT}/include/user_settings.h "
                                            " (please move it to ${WOLFSSL_PROJECT_DIR}/include/user_settings.h )")
                        # Abort CMake after fatal error.
                    else()
                        # we won't overwrite an existing user settings file, just note that we already have one:
                        if( EXISTS "${WOLFSSL_PROJECT_DIR}/include/user_settings.h" )
                            message(STATUS "Using existing wolfSSL user_settings.h in "
                                            "${WOLFSSL_PROJECT_DIR}/include/user_settings.h")
                        else()
                            message(STATUS "Installing wolfSSL user_settings.h to "
                                            "${WOLFSSL_PROJECT_DIR}/include/user_settings.h")
                            file(COPY "${WOLFSSL_ROOT}/IDE/Espressif/ESP-IDF/user_settings.h"
                            DESTINATION "${CMAKE_HOME_DIRECTORY}/wolfssl/include/")
                        endif()
                    endif() # user_settings.h

                    # next check if there's a [root]/include/config.h
                    if( EXISTS "${WOLFSSL_ROOT}/include/config.h" )
                        message(STATUS "******************************************************************************")
                        message(STATUS "******************************************************************************")
                        message(STATUS "Found stray wolfSSL config.h in ${WOLFSSL_ROOT}/include/config.h"              )
                        message(STATUS "  Please move it to ${WOLFSSL_PROJECT_DIR}/include/config.h"                   )
                        message(STATUS "******************************************************************************")
                        message(STATUS "******************************************************************************")
                    else()
                        # we won't overwrite an existing user settings file, just note that we already have one:
                        if( EXISTS "${WOLFSSL_PROJECT_DIR}/include/config.h" )
                            message(STATUS "Using existing wolfSSL config.h           ${WOLFSSL_PROJECT_DIR}/include/config.h")
                        else()
                            message(STATUS "Installing wolfSSL config.h to            ${WOLFSSL_PROJECT_DIR}/include/config.h")
                            file(COPY   "${WOLFSSL_ROOT}/IDE/Espressif/ESP-IDF/dummy_config_h" DESTINATION "${WOLFSSL_PROJECT_DIR}/include/")
                            file(RENAME "${WOLFSSL_PROJECT_DIR}/include/dummy_config_h" "${WOLFSSL_PROJECT_DIR}/include/config.h")
                        endif() # Project config.h
                    endif() # WOLFSSL_ROOT config.h
                    message(STATUS "************************************************************************************************")
                    message(STATUS "")
                endif()

            else()
                # we did not find a ./components/wolfssl/include/ directory from this pass of cmake.
                if($WOLFSSL_FOUND_IDF)
                    message(STATUS "")
                    message(STATUS "WARNING: wolfSSL not found.")
                    message(STATUS "")
                else()
                    # probably needs to be re-parsed by Espressif
                    message(STATUS "wolfSSL found IDF. Project Source:${PROJECT_SOURCE_DIR}")
                endif() # else we have not found ESP-IDF yet
            endif() # else not a local wolfSSL component

        endif() #else not an ESP-IDF component
    endif() # else not local copy and EDP-IDF wolfSSL


    # RTOS_IDF_PATH is typically:
    # "/Users/{username}/Desktop/esp-idf/components/freertos/include/freertos"
    # depending on the environment, we may need to swap backslashes with forward slashes
    string(REPLACE "\\" "/" RTOS_IDF_PATH "$ENV{IDF_PATH}/components/freertos/FreeRTOS-Kernel/include/freertos")

	if(WOLFSSL_ROOT)
	    string(REPLACE "\\" "/" WOLFSSL_ROOT ${WOLFSSL_ROOT})
	endif()

    if(IS_DIRECTORY "${RTOS_IDF_PATH}")
        message(STATUS "Found current RTOS path: ${RTOS_IDF_PATH}")
    else()
        # ESP-IDF prior version 4.4x has a different RTOS directory structure
        string(REPLACE "\\" "/" RTOS_IDF_PATH "$ENV{IDF_PATH}/components/freertos/include/freertos")
        if(IS_DIRECTORY "${RTOS_IDF_PATH}")
            message(STATUS "Found legacy RTOS path: ${RTOS_IDF_PATH}")
        else()
            message(STATUS "Could not find RTOS path")
        endif()
    endif()
    message(STATUS "THIS_IDF_PATH = $THIS_IDF_PATH")
    # wolfSSL-specific include directories
    set(COMPONENT_ADD_INCLUDEDIRS
        "./include" # this is the location of local project wolfssl user_settings.h
        "\"${WOLFSSL_ROOT}/\""
        "\"${WOLFSSL_ROOT}/wolfssl/\""
        "\"${WOLFSSL_ROOT}/wolfssl/wolfcrypt/\""
        "\"${WOLFSSL_ROOT}/wolfssl/wolfcrypt/port/Espressif\""
        "\"${RTOS_IDF_PATH}/\""
        # wolfSSL release after v5.7 includes WiFi, time, and mem/debug helpers
        "${THIS_IDF_PATH}/components/esp_event/include"
        "${THIS_IDF_PATH}/components/esp_netif/include"
        "${THIS_IDF_PATH}/components/esp_wifi/include"
        )

    # Optionally include cryptoauthlib if present
    if(IS_DIRECTORY ${IDF_PATH}/components/cryptoauthlib)
        list(APPEND COMPONENT_ADD_INCLUDEDIRS "../cryptoauthlib/lib")
    endif()

    list(APPEND COMPONENT_ADD_INCLUDEDIRS "\"${WOLFSSL_ROOT}/wolfssl/\"")
    list(APPEND COMPONENT_ADD_INCLUDEDIRS "\"${WOLFSSL_ROOT}/wolfssl/wolfcrypt/\"")


    # Some files are known to be included elsewhere, or not used for Espressif
    set(COMPONENT_SRCEXCLUDE
        "\"${WOLFSSL_ROOT}/src/bio.c\""
        "\"${WOLFSSL_ROOT}/src/conf.c\""
        "\"${WOLFSSL_ROOT}/src/misc.c\""
        "\"${WOLFSSL_ROOT}/src/pk.c\""
        "\"${WOLFSSL_ROOT}/src/ssl_asn1.c\""    # included by ssl.c
        "\"${WOLFSSL_ROOT}/src/ssl_bn.c\""      # included by ssl.c
        "\"${WOLFSSL_ROOT}/src/ssl_certman.c\"" # included by ssl.c
        "\"${WOLFSSL_ROOT}/src/ssl_crypto.c\""  # included by ssl.c
        "\"${WOLFSSL_ROOT}/src/ssl_load.c\""    # included by ssl.c
        "\"${WOLFSSL_ROOT}/src/ssl_misc.c\""    # included by ssl.c
        "\"${WOLFSSL_ROOT}/src/ssl_p7p12.c\""   # included by ssl.c
        "\"${WOLFSSL_ROOT}/src/ssl_sess.c\""    # included by ssl.c
        "\"${WOLFSSL_ROOT}/src/x509.c\""
        "\"${WOLFSSL_ROOT}/src/x509_str.c\""
        "\"${WOLFSSL_ROOT}/wolfcrypt/src/ext_kyber.c\""     # external non-wolfssl Kyber disabled by default
        "\"${WOLFSSL_ROOT}/wolfssl/wolfcrypt/ext_kyber.h\"" # external non-wolfssl Kyber disabled by default
        "\"${WOLFSSL_ROOT}/wolfcrypt/src/evp.c\""
        "\"${WOLFSSL_ROOT}/wolfcrypt/src/misc.c\""
        "\"${WOLFSSL_ROOT}/wolfcrypt/src/sp_sm2_arm32.c\""
        "\"${WOLFSSL_ROOT}/wolfcrypt/src/sp_sm2_arm64.c\""
        "\"${WOLFSSL_ROOT}/wolfcrypt/src/sp_sm2_armthumb.c\""
        "\"${WOLFSSL_ROOT}/wolfcrypt/src/sp_sm2_c32.c\""
        "\"${WOLFSSL_ROOT}/wolfcrypt/src/sp_sm2_c64.c\""
        "\"${WOLFSSL_ROOT}/wolfcrypt/src/sp_sm2_cortexm.c\""
        "\"${WOLFSSL_ROOT}/wolfcrypt/src/sp_sm2_x86_64.c\""
        "\"${WOLFSSL_ROOT}/wolfcrypt/src/sp_sm2_x86_64_asm.S\""
        "\"${WOLFSSL_ROOT}/examples\"" # Examples are distributed in Managed Components, but not part of a project.
        "\"${EXCLUDE_ASM}\""
        )

    spaces2list(COMPONENT_REQUIRES)

    separate_arguments(COMPONENT_SRCDIRS NATIVE_COMMAND "${COMPONENT_SRCDIRS}")
    separate_arguments(COMPONENT_SRCEXCLUDE NATIVE_COMMAND "${COMPONENT_SRCEXCLUDE}")
    separate_arguments(COMPONENT_ADD_INCLUDEDIRS NATIVE_COMMAND "${COMPONENT_ADD_INCLUDEDIRS}")

    #
    # See https://docs.espressif.com/projects/esp-idf/en/latest/esp32/api-guides/build-system.html#example-component-requirements
    #
    message(STATUS "COMPONENT_SRCDIRS = ${COMPONENT_SRCDIRS}")
    message(STATUS "COMPONENT_ADD_INCLUDEDIRS = ${COMPONENT_ADD_INCLUDEDIRS}")
    message(STATUS "COMPONENT_REQUIRES = ${COMPONENT_REQUIRES}")
    message(STATUS "COMPONENT_SRCEXCLUDE = ${COMPONENT_SRCEXCLUDE}")

    #
    # see https://docs.espressif.com/projects/esp-idf/en/stable/esp32/migration-guides/release-5.x/build-system.html?highlight=space%20path
    #
    set(EXTRA_COMPONENT_DIRS "${COMPONENT_SRCDIRS}")

    if(WOLFSSL_ROOT)
        # Only register the component if we found wolfSSL source.
        # This is important to allow Cmake to finish to completion, otherwise the UI
        # may not be able to display the Kconfig settings to fix a bad or missing source.
        idf_component_register(
                                SRC_DIRS "${COMPONENT_SRCDIRS}"
                                INCLUDE_DIRS "${COMPONENT_ADD_INCLUDEDIRS}"
                                REQUIRES "${COMPONENT_REQUIRES}"
                                EXCLUDE_SRCS "${COMPONENT_SRCEXCLUDE}"
                                PRIV_REQUIRES
                                  "${THIS_ESP_TLS}"
                                  "${THIS_INCLUDE_TIMER}"
                                  "${THIS_INCLUDE_DRIVER}" # this will typically only be needed for wolfSSL benchmark
                               )
    else()
        # Register the component simply to allow CMake to complete, but there's no wolfSSL source.
        # Expect many other errors, but the project should at least be loadable and UI can edit Kconfig settings.
        idf_component_register()
        message(STATUS "Warning: wolfSSL component not registered as no source code found (WOLFSSL_ROOT is blank)")
    endif()

# function(WOLFSSL_INIT_CERT_BUNDLE)
if( CONFIG_WOLFSSL_CERTIFICATE_BUNDLE
    AND NOT CONFIG_WOLFSSL_CERTIFICATE_BUNDLE_DEFAULT_NONE
    AND NOT ("${CONFIG_TARGET_PLATFORM}" STREQUAL "esp8266")
  )
    if (CMAKE_BUILD_EARLY_EXPANSION)
        message(ERROR "Bundle Cert initialization must occur during CMAKE_BUILD_EARLY_EXPANSION")
    endif()
    # reminder: we need a value for wolfSSL root first!
    if( "${WOLFSSL_ROOT}" STREQUAL "" )
        message(ERROR "Certificate bundles need a value for WOLFSSL_ROOT")
    endif()
    set(WOLFSSL_ESP_CRT_BUNDLE_DIR ${WOLFSSL_ROOT}/wolfcrypt/src/port/Espressif/esp_crt_bundle)
    message(STATUS "WOLFSSL_ESP_CRT_BUNDLE_DIR=${WOLFSSL_ESP_CRT_BUNDLE_DIR}")
    if(EXISTS "${WOLFSSL_ESP_CRT_BUNDLE_DIR}")
        set(bundle_name "x509_crt_bundle_wolfssl")

        # For now the certs are in the same directory
        set(DEFAULT_CRT_DIR "${WOLFSSL_ESP_CRT_BUNDLE_DIR}")

        # Generate custom certificate bundle using the generate_cert_bundle utility
        set(GENERATE_CERT_BUNDLEPY ${python} ${WOLFSSL_ESP_CRT_BUNDLE_DIR}/gen_crt_bundle.py)

        if(CONFIG_WOLFSSL_CERTIFICATE_BUNDLE_DEFAULT_FULL)
            list(APPEND crt_paths ${DEFAULT_CRT_DIR}/cacrt_all.pem ${DEFAULT_CRT_DIR}/cacrt_local.pem)
        elseif(CONFIG_WOLFSSL_CERTIFICATE_BUNDLE_DEFAULT_CMN)
            list(APPEND crt_paths ${DEFAULT_CRT_DIR}/cacrt_all.pem ${DEFAULT_CRT_DIR}/cacrt_local.pem)
            list(APPEND args --filter ${DEFAULT_CRT_DIR}/cmn_crt_authorities.csv)
        endif()

        # Add deprecated root certs if enabled. This config is not visible if the default cert
        # bundle is not selected
        if(CONFIG_WOLFSSL_CERTIFICATE_BUNDLE_DEPRECATED_LIST)
            list(APPEND crt_paths ${DEFAULT_CRT_DIR}/cacrt_deprecated.pem)
        endif()

        if(CONFIG_WOLFSSL_CUSTOM_CERTIFICATE_BUNDLE)
            get_filename_component(custom_bundle_path
              ${CONFIG_WOLFSSL_CUSTOM_CERTIFICATE_BUNDLE_PATH} ABSOLUTE BASE_DIR "${project_dir}")
            list(APPEND crt_paths ${custom_bundle_path})
            message(STATUS "Using a custom wolfSSL bundle path: ${custom_bundle_path}")
        else()
            message(STATUS "Not using a custom wolfSSL bundle path.")
        endif()
        list(APPEND args --input ${crt_paths} -q)

        message(STATUS "CMAKE_CURRENT_BINARY_DIR: ${CMAKE_CURRENT_BINARY_DIR}")
        get_filename_component(crt_bundle
            ${bundle_name}
            ABSOLUTE BASE_DIR "${CMAKE_CURRENT_BINARY_DIR}")

        message(STATUS "Setting up bundle generate: ${GENERATE_CERT_BUNDLEPY} ${args}")
        message(STATUS "Depends on custom bundle path: ${custom_bundle_path}")
        message(STATUS "crt_bundle ${crt_bundle}")
        message(STATUS "COMPONENT_LIB ${COMPONENT_LIB}")
        message(STATUS "GENERATE_CERT_BUNDLEPY ${GENERATE_CERT_BUNDLEPY}")
        message(STATUS "args ${args}")
        message(STATUS "cert_bundle ${cert_bundle}")

        # Generate bundle according to config
        # File is generated at build time, not cmake load
        add_custom_command(OUTPUT ${crt_bundle}
            COMMAND ${GENERATE_CERT_BUNDLEPY} ARGS ${args}
            DEPENDS ${custom_bundle_path}
            VERBATIM)

        if(EXISTS "${crt_bundle}")
            message(STATUS "Bundle file exists from prior build: ${crt_bundle}")
        else()
            message(STATUS "Bundle file expected during next build: ${crt_bundle}")
        endif()

        # Reminder the file is generated at build time, not cmake load time.
        message(STATUS "wolfSSL Cert Bundle File to be created at build time in: ${crt_bundle}")

        add_custom_target(custom_wolfssl_bundle DEPENDS ${cert_bundle})

        # the wolfSSL crtificate bundle is baked into wolfSSL
        add_dependencies(${COMPONENT_LIB} custom_wolfssl_bundle)

        # COMPONENT_LIB may vary: __idf_wolfssl, __idf_esp_wolfssl, etc
        # target_add_binary_data(__idf_wolfssl ${crt_bundle} BINARY)
        target_add_binary_data(${COMPONENT_LIB} ${crt_bundle} BINARY)
        set_property(DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
                     APPEND PROPERTY ADDITIONAL_CLEAN_FILES
                     "${crt_bundle}")
    else()
        message(STATUS "WARNING: CONFIG_WOLFSSL_CERTIFICATE_BUNDLE enabled but directory not found: ${WOLFSSL_ESP_CRT_BUNDLE_DIR}")
    endif()
endif()

# endfunction() # WOLFSSL_INIT_CERT_BUNDLE

    # Some optional diagnostics. Verbose ones are truncated.
    if (VERBOSE_COMPONENT_MESSAGES)
        get_cmake_property(_variableNames VARIABLES)
        list (SORT _variableNames)
        message(STATUS "")
        message(STATUS "ALL VARIABLES BEGIN")
        message(STATUS "")
        foreach (_variableName ${_variableNames})
            if (      ("${_variableName}" STREQUAL "bootloader_binary_files")
                    OR ("${_variableName}" STREQUAL "Component paths")
                    OR ("${_variableName}" STREQUAL "component_targets")
                    OR ("${_variableName}" STREQUAL "__COMPONENT_TARGETS")
                    OR ("${_variableName}" STREQUAL "CONFIGS_LIST")
                    OR ("${_variableName}" STREQUAL "__CONFIG_VARIABLES")
                    OR ("${_variableName}" STREQUAL "val")
                    OR ("${_variableName}" MATCHES "^__idf_")
               )
                # Truncate the displayed value:
                string(SUBSTRING "${${_variableName}}" 0 70 truncatedValue)
                message(STATUS "${_variableName} = ${truncatedValue} ... (truncated)")
            else()
                message(STATUS "${_variableName}=${${_variableName}}")
            endif()
        endforeach()
        message(STATUS "")
        message(STATUS "ALL VARIABLES END")
        message(STATUS "")
    endif()

    # target_sources(wolfssl PRIVATE  "\"${WOLFSSL_ROOT}/wolfssl/\""  "\"${WOLFSSL_ROOT}/wolfssl/wolfcrypt\"")
    message(STATUS "DETECTED_PROJECT_NAME=${CMAKE_PROJECT_NAME}")
    message(STATUS "COMPONENT_TARGET=${COMPONENT_TARGET}")
    target_compile_definitions(${COMPONENT_TARGET} PRIVATE DETECTED_PROJECT_NAME="${CMAKE_PROJECT_NAME}")
    if( "${CMAKE_PROJECT_NAME}" STREQUAL "esp_http_client_example" )
        target_compile_definitions(${COMPONENT_TARGET} PRIVATE APP_ESP_HTTP_CLIENT_EXAMPLE="y")
    endif()

endif() # CMAKE_BUILD_EARLY_EXPANSION



# check to see if there's both a local copy and EDP-IDF copy of the wolfssl components
if( EXISTS "${WOLFSSL_PROJECT_DIR}" AND EXISTS "$ENV{IDF_PATH}/components/wolfssl/" )
    message(STATUS "")
    message(STATUS "")
    message(STATUS "********************************************************************")
    message(STATUS "WARNING: Found components/wolfssl in both local project and IDF_PATH")
    message(STATUS "********************************************************************")
    message(STATUS "")
endif()
# end multiple component check


#
# LIBWOLFSSL_SAVE_INFO(VAR_OUPUT THIS_VAR VAR_RESULT)
#
# Save the THIS_VAR as a string in a macro called VAR_OUPUT
#
# VAR_OUPUT:  the name of the macro to define
# THIS_VAR:   the OUTPUT_VARIABLE result from a execute_process()
# VAR_RESULT: the RESULT_VARIABLE from a execute_process(); "0" if successful.
#
function ( LIBWOLFSSL_SAVE_INFO VAR_OUPUT THIS_VAR VAR_RESULT )
    # is the RESULT_VARIABLE output value 0? If so, IS_VALID_VALUE is true.
    string(COMPARE EQUAL "${VAR_RESULT}" "0" IS_VALID_VALUE)

    # if we had a successful operation, save the THIS_VAR in VAR_OUPUT
    if(${IS_VALID_VALUE})
        # strip newline chars in THIS_VAR parameter and save in VAR_VALUE
        string(REPLACE "\n" ""  VAR_VALUE  ${THIS_VAR})

        # we'll could percolate the value to the parent for possible later use
        # set(${VAR_OUPUT} ${VAR_VALUE} PARENT_SCOPE)

        # but we're only using it here in this function
        set(${VAR_OUPUT} ${VAR_VALUE})

        # we'll print what we found to the console
        message(STATUS "Found ${VAR_OUPUT}=${VAR_VALUE}")

        # the interesting part is defining the VAR_OUPUT name a value to use in the app
        add_compile_definitions(${VAR_OUPUT}=\"${VAR_VALUE}\")
    else()
        # if we get here, check the execute_process command and parameters.
        message(STATUS "LIBWOLFSSL_SAVE_INFO encountered a non-zero VAR_RESULT")
        set(${VAR_OUPUT} "Unknown")
    endif()
endfunction() # LIBWOLFSSL_SAVE_INFO

execute_process(
    COMMAND ${git_cmd} "rev-parse" "--is-inside-work-tree"
    OUTPUT_VARIABLE IS_GIT_REPO
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)

# create some programmatic #define values that will be used by ShowExtendedSystemInfo().
# see wolfcrypt\src\port\Espressif\esp32_utl.c
if(NOT CMAKE_BUILD_EARLY_EXPANSION AND WOLFSSL_ROOT AND (IS_GIT_REPO STREQUAL "true"))
    set (git_cmd "git")
    message(STATUS "Adding macro definitions:")

    # LIBWOLFSSL_VERSION_GIT_ORIGIN: git config --get remote.origin.url
    execute_process(WORKING_DIRECTORY ${WOLFSSL_ROOT} COMMAND ${git_cmd} "config" "--get" "remote.origin.url"
                    OUTPUT_VARIABLE TMP_OUT RESULT_VARIABLE TMP_RES ERROR_QUIET  )
    LIBWOLFSSL_SAVE_INFO(LIBWOLFSSL_VERSION_GIT_ORIGIN "${TMP_OUT}" "${TMP_RES}")

    # LIBWOLFSSL_VERSION_GIT_BRANCH: git rev-parse --abbrev-ref HEAD
    execute_process(WORKING_DIRECTORY ${WOLFSSL_ROOT} COMMAND ${git_cmd} "rev-parse" "--abbrev-ref" "HEAD"
                    OUTPUT_VARIABLE TMP_OUT RESULT_VARIABLE TMP_RES ERROR_QUIET  )
    LIBWOLFSSL_SAVE_INFO(LIBWOLFSSL_VERSION_GIT_BRANCH "${TMP_OUT}" "${TMP_RES}")

    # LIBWOLFSSL_VERSION_GIT_HASH: git rev-parse HEAD
    execute_process(WORKING_DIRECTORY ${WOLFSSL_ROOT} COMMAND ${git_cmd} "rev-parse" "HEAD"
                    OUTPUT_VARIABLE TMP_OUT RESULT_VARIABLE TMP_RES ERROR_QUIET  )
    LIBWOLFSSL_SAVE_INFO(LIBWOLFSSL_VERSION_GIT_HASH "${TMP_OUT}" "${TMP_RES}")

    # LIBWOLFSSL_VERSION_GIT_SHORT_HASH: git rev-parse --short HEAD
    execute_process(WORKING_DIRECTORY ${WOLFSSL_ROOT} COMMAND ${git_cmd} "rev-parse" "--short" "HEAD"
                    OUTPUT_VARIABLE TMP_OUT RESULT_VARIABLE TMP_RES ERROR_QUIET )
    LIBWOLFSSL_SAVE_INFO(LIBWOLFSSL_VERSION_GIT_SHORT_HASH "${TMP_OUT}" "${TMP_RES}")

    # LIBWOLFSSL_VERSION_GIT_HASH_DATE git show --no-patch --no-notes --pretty=\'\%cd\'
    execute_process(WORKING_DIRECTORY ${WOLFSSL_ROOT} COMMAND ${git_cmd}
                    "show" "--no-patch" "--no-notes" "--pretty=\'\%cd\'"
                    OUTPUT_VARIABLE TMP_OUT RESULT_VARIABLE TMP_RES  )
    LIBWOLFSSL_SAVE_INFO(LIBWOLFSSL_VERSION_GIT_HASH_DATE "${TMP_OUT}" "${TMP_RES}")

    LIBWOLFSSL_SAVE_INFO(LIBWOLFSSL_VERSION_WOLFSSL_ROOT "${WOLFSSL_ROOT}" "${TMP_RES}")

endif()

# Ensure flag "-DWOLFSSL_ESPIDF" is already in CMAKE_C_FLAGS if not yet found from project
string(FIND "${CMAKE_C_FLAGS}" "-DWOLFSSL_ESPIDF" FLAG_ALRREADY_FOUND_WOLFSSL_ESPIDF)

if(FLAG_ALRREADY_FOUND_WOLFSSL_ESPIDF EQUAL -1)
    # Flag not found, append it
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_ESPIDF")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_USER_SETTINGS")
endif()

if(WOLFSSL_ROOT)
    message(STATUS "Using wolfSSL in ${WOLFSSL_ROOT}")

    # PlatformIO does not process script from from the Espressif cmake process.
    # We need to know where wolfSSL source code was found, so save it in the
    # PIO_WOLFSSL_ROOT environment variable to later be read by extra_script.py

    set(ENV{PIO_WOLFSSL_ROOT} "${WOLFSSL_ROOT}")
    message(STATUS "PIO_WOLFSSL_ROOT =  $ENV{PIO_WOLFSSL_ROOT}")
    message(STATUS "PLATFORMIO_BUILD_DIR = $ENV{PLATFORMIO_BUILD_DIR}")
    # See esp-tls Kconfig; menu "ESP-TLS", ESP_TLS_LIBRARY_CHOOSE
    if(CONFIG_ESP_TLS_USING_WOLFSSL)
        if ( ("${CONFIG_TARGET_PLATFORM}" STREQUAL "esp8266") OR ("${IDF_TARGET}" STREQUAL "esp8266") )
            message(STATUS "This version of wolfSSL is not supported on the ESP8266 esp-tls at this time. Check ESP-TLS config")
        else()
            message(STATUS "wolfSSL will be used for ESP-TLS")
        endif()
    else()
        message(STATUS "WARNING: wolfSSL NOT selected for ESP-TLS. Features and performance will be limited.")
    endif()
else()
    message(STATUS "")
    message(STATUS "Consider setting WOLFSSL_ROOT environment variable, use Kconfig setting, or set manually in this cmake file, above.")
    message(STATUS "")
    message(STATUS "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    message(STATUS "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    message(STATUS "ERROR: Could not find wolfSSL Source Code")
    message(STATUS "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
    message(STATUS "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!")
endif()

message(STATUS "************************************************************************************************")
message(STATUS "wolfSSL component config complete!")
message(STATUS "************************************************************************************************")
