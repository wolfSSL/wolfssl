# wolfSSL Espressif Example Project CMakeLists.txt
#   v1.3
#
# The following lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
message(STATUS "Begin project ${CMAKE_PROJECT_NAME}")

cmake_minimum_required(VERSION 3.16)

# Optional no watchdog typically used for test & benchmark
add_compile_definitions(WOLFSSL_ESP_NO_WATCHDOG=1)

# The wolfSSL CMake file should be able to find the source code.
# Otherwise, assign an environment variable or set it here:
#
# set(WOLFSSL_ROOT "~/workspace/wolfssl-other-source")
#
# Optional WOLFSSL_CMAKE_SYSTEM_NAME detection to find
# USE_MY_PRIVATE_CONFIG path for my_private_config.h
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

message(STATUS "begin optional PROTOCOL_EXAMPLES_DIR include")
if(0)
    # This example uses an extra component for common functions such as Wi-Fi and Ethernet connection.
    set (PROTOCOL_EXAMPLES_DIR $ENV{IDF_PATH}/examples/common_components/protocol_examples_common)

    if (EXISTS "${PROTOCOL_EXAMPLES_DIR}")
        message(STATUS "Found PROTOCOL_EXAMPLES_DIR=${PROTOCOL_EXAMPLES_DIR}")
        set(EXTRA_COMPONENT_DIRS $ENV{IDF_PATH}/examples/common_components/protocol_examples_common)
        set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DFOUND_PROTOCOL_EXAMPLES_DIR")
    else()
        message(STATUS "NOT FOUND: PROTOCOL_EXAMPLES_DIR=${PROTOCOL_EXAMPLES_DIR}")
    endif()
endif()
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
message(STATUS "end optional include")

project(wolfssl_test)
message(STATUS "end project")
