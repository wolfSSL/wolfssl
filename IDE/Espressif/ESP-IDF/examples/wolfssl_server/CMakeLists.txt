# wolfSSL Espressif Example Project CMakeLists.txt
#   v5.8.2.001
#
# The following lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
message(STATUS "Begin project ${CMAKE_PROJECT_NAME}")

cmake_minimum_required(VERSION 3.16)
set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -DWOLFSSL_USER_SETTINGS")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DWOLFSSL_USER_SETTINGS")

# Optionally set flag for using a private include. See wolfcrypt/port/Espressif/esp-sdk-lib.h
if(  "$ENV{CONFIG_WOLFSSL_USE_MY_PRIVATE_CONFIG}" STREQUAL "1" )
    message(STATUS "Setting CONFIG_WOLFSSL_USE_MY_PRIVATE_CONFIG from environment variable")
    set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS}   -DCONFIG_WOLFSSL_USE_MY_PRIVATE_CONFIG=1")
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DCONFIG_WOLFSSL_USE_MY_PRIVATE_CONFIG=1")
else()
    message(STATUS "CONFIG_WOLFSSL_USE_MY_PRIVATE_CONFIG not set, not using private config.")
endif()

# Different ESP-IDF versions have different lock files.
# Not starting fresh has unintuitive results.
# So force a fresh dependencies.lock by deleting the current one:
file(REMOVE "./dependencies.lock")

# Force custom partition table regardless of IDE presets
set(PARTITION_TABLE_CUSTOM ON CACHE BOOL "" FORCE)
set(PARTITION_TABLE_FILENAME "${CMAKE_SOURCE_DIR}/partitions_singleapp_large.csv" CACHE STRING "" FORCE)

if("${IDF_TARGET}" STREQUAL "linux")
    set(COMPONENTS main)
endif()

# For the main project using ESP-IDF version 6 or greater.
# Numerous "dangerous relocation: call8: call target out of range: memcpy" errors encountered
# So we'll allow long calls with the `-mlongcalls` compiler option for all components.
if(IDF_VERSION_MAJOR GREATER_EQUAL 6)
    if(IDF_TARGET STREQUAL "esp32" OR IDF_TARGET STREQUAL "esp32s2" OR IDF_TARGET STREQUAL "esp32s3")
        message(STATUS "Adding mlongcalls")
        add_compile_options(-mlongcalls)
        add_link_options(-mlongcalls)
        set(CMAKE_C_FLAGS   "${CMAKE_C_FLAGS} -mlongcalls")
        set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -mlongcalls")
    endif()
endif()

# Optional no watchdog typically used for test & benchmark
if (idf_target STREQUAL "esp8266" OR IDF_TARGET STREQUAL "esp8266" OR IDF_VERSION_MAJOR VERSION_LESS "5.0")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_ESP_NO_WATCHDOG=1")
else()
    add_compile_definitions(WOLFSSL_ESP_NO_WATCHDOG=1)
endif()

# The wolfSSL CMake file should be able to find the source code.
# Otherwise, assign an environment variable or set it here:
#
# set(WOLFSSL_ROOT "~/workspace/wolfssl-other-source")
#
# Optional WOLFSSL_CMAKE_SYSTEM_NAME detection to find
# USE_MY_PRIVATE_CONFIG path for my_private_config.h
#   See: wolfcrypt/port/Espressif/esp-sdk-lib.h
#
# Expected path varies:
#
#     WSL:  /mnt/c/workspace
#   Linux:  ~/workspace
# Windows:  C:\workspace
#


if(WIN32)
    # Windows-specific configuration here
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_CMAKE_SYSTEM_NAME_WINDOWS")
    message(STATUS "Detected Windows")
endif()
if(CMAKE_HOST_UNIX)
    message(STATUS "Detected UNIX")
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
    # Apple-specific configuration here
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_CMAKE_SYSTEM_NAME_APPLE")
    message(STATUS "Detected Apple")
endif()
# End optional WOLFSSL_CMAKE_SYSTEM_NAME

# This example uses an extra component for common functions such as Wi-Fi and Ethernet connection.
# set (PROTOCOL_EXAMPLES_DIR $ENV{IDF_PATH}/examples/common_components/protocol_examples_common)
string(REPLACE "\\" "/" PROTOCOL_EXAMPLES_DIR "$ENV{IDF_PATH}/examples/common_components/protocol_examples_common")

if (EXISTS "${PROTOCOL_EXAMPLES_DIR}")
    message(STATUS "Found PROTOCOL_EXAMPLES_DIR=${PROTOCOL_EXAMPLES_DIR}")
    set(EXTRA_COMPONENT_DIRS $ENV{IDF_PATH}/examples/common_components/protocol_examples_common)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DFOUND_PROTOCOL_EXAMPLES_DIR")
else()
    message(STATUS "NOT FOUND: PROTOCOL_EXAMPLES_DIR=${PROTOCOL_EXAMPLES_DIR}")
endif()

# Find the user name to search for possible "wolfssl-username"
# Reminder: Windows is  %USERNAME%, Linux is $USER
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

# Check that there are not conflicting wolfSSL components
# The ESP Registry Component will be in ./managed_components/wolfssl__wolfssl
# The local component wolfSSL directory will be in ./components/wolfssl
message(STATUS "Checking for wolfSSL as Managed Component or not... ${CMAKE_HOME_DIRECTORY}")
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
elseif(EXISTS "${CMAKE_HOME_DIRECTORY}/components/wolfssl")
    # A standard project component (not a Managed Component)
    message(STATUS "No conflicting wolfSSL components found.")
    set(WOLFSSL_PATH "${CMAKE_HOME_DIRECTORY}/components/wolfssl")
elseif(EXISTS "${CMAKE_HOME_DIRECTORY}/managed_components/wolfssl__wolfssl")
    # The official Managed Component called wolfssl from the wolfssl user.
    message(STATUS "No conflicting wolfSSL components found as a Managed Component.")
    set(WOLFSSL_PATH "${CMAKE_HOME_DIRECTORY}/managed_components/wolfssl__wolfssl")
elseif(EXISTS "${CMAKE_HOME_DIRECTORY}/managed_components/gojimmypi__mywolfssl")
    # There is a known gojimmypi staging component available for anyone:
    message(STATUS "No conflicting wolfSSL components found as a gojimmypi staging Managed Component.")
elseif(EXISTS "${CMAKE_HOME_DIRECTORY}/managed_components/${THIS_USER}__mywolfssl")
    # Other users with permissions might publish their own mywolfssl staging Managed Component
    message(STATUS "No conflicting wolfSSL components found as a Managed Component.")
    set(WOLFSSL_PATH "${CMAKE_HOME_DIRECTORY}/managed_components/${THIS_USER}__mywolfssl")
else()
    message(STATUS "WARNING: wolfssl component directory not found.")
endif()

# message(STATUS "EXTRA_COMPONENT_DIRS WOLFSSL_PATH: ${WOLFSSL_PATH}")
# list(APPEND EXTRA_COMPONENT_DIRS ${WOLFSSL_PATH})

# Not only is a project-level "set(COMPONENTS" not needed here, this will cause
# an unintuitive error about  Unknown CMake command "esptool_py_flash_project_args".

if(0)
    message(STATUS "Begin optional PROTOCOL_EXAMPLES_DIR include")
    # This example uses an extra component for common functions such as Wi-Fi and Ethernet connection.
    set (PROTOCOL_EXAMPLES_DIR $ENV{IDF_PATH}/examples/common_components/protocol_examples_common)

    if (EXISTS "${PROTOCOL_EXAMPLES_DIR}")
        message(STATUS "Found PROTOCOL_EXAMPLES_DIR=${PROTOCOL_EXAMPLES_DIR}")
        set(EXTRA_COMPONENT_DIRS $ENV{IDF_PATH}/examples/common_components/protocol_examples_common)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DFOUND_PROTOCOL_EXAMPLES_DIR")
    else()
        message(STATUS "NOT FOUND: PROTOCOL_EXAMPLES_DIR=${PROTOCOL_EXAMPLES_DIR}")
    endif()
    message(STATUS "End optional PROTOCOL_EXAMPLES_DIR include")
endif()

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

message(STATUS "Checking Project CONFIG_WOLFSSL_FORCE_V6_INTELLISENSE_FIX=$ENV{CONFIG_WOLFSSL_FORCE_V6_INTELLISENSE_FIX}")
# Optionally force syntax highlighting fix in Visual Studio 2022 for ESP-IDF v6
# See https://sysprogs.com/w/forums/topic/espressif-esp-idf-v6-0-intellisense-error-invalid-value-gnu2b-in-stdgnu2b/
# To resolve, enter the text in VisualGDB Project Properties - Intellisense Settings Tab, "Additional flags for C files":
#   -std=gnu17
# And set here:
if(  "$ENV{CONFIG_WOLFSSL_FORCE_V6_INTELLISENSE_FIX}" STREQUAL "1" )
    set(PREFERRED_DIALECT "gnu17")
    if(DEFINED IDF_VERSION_MAJOR AND IDF_VERSION_MAJOR GREATER_EQUAL 6)
        message(STATUS "-- Found CONFIG_WOLFSSL_FORCE_V6_INTELLISENSE_FIX, replacing -std=gnu2b with -std=${PREFERRED_DIALECT}")
        if(CMAKE_C_COMPILER_ID MATCHES "Clang")
          string(REPLACE "-std=gnu2b" "-std=${PREFERRED_DIALECT}" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
        endif()
    else()
        message(STATUS "-- Visual Studio Intellisense Fix not needed for this ESP-IDF version=${IDF_VERSION_MAJOR}")
    endif()
else()
    message(STATUS "-- Not replacing -std=gnu2b with -std=${PREFERRED_DIALECT} for Viosual Studio Intellisense fix")
    message(STATUS "-- To enable, define environment variable: CONFIG_WOLFSSL_FORCE_V6_INTELLISENSE_FIX=1")
endif()

# Once the project is loaded, next check for ESP-IDF version 6 or greater.
# Numerous "dangerous relocation: call8: call target out of range: memcpy" errors encountered
# So we'll allow long calls with the `-mlongcalls` compiler option for all components.
if(IDF_VERSION_MAJOR GREATER_EQUAL 6)
    if(IDF_TARGET STREQUAL "esp32" OR IDF_TARGET STREQUAL "esp32s2" OR IDF_TARGET STREQUAL "esp32s3")
        message(STATUS "mlongcalls for all components")
        idf_build_set_property(COMPILE_OPTIONS "-mlongcalls" APPEND)
    endif()
endif()

project(wolfssl_server)
message(STATUS "end project")
