# wolfSSL Espressif Example Project CMakeLists.txt
#   v1.0
#
# The following lines of boilerplate have to be in your project's
# CMakeLists in this exact order for cmake to work correctly
cmake_minimum_required(VERSION 3.16)

add_compile_options(-DWOLFSSL_ESP_NO_WATCHDOG=1)
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

# Optionally specify a location for wolfSSL component source code
# set(WOLFSSL_ROOT "c:/mydir/wolfssl" )
# This example uses an extra component for common functions such as Wi-Fi and Ethernet connection.
# set (PROTOCOL_EXAMPLES_DIR $ENV{IDF_PATH}/examples/common_components/protocol_examples_common)
#
#if (EXISTS "${PROTOCOL_EXAMPLES_DIR}")
#    message("Found PROTOCOL_EXAMPLES_DIR=${PROTOCOL_EXAMPLES_DIR}")
#    set(EXTRA_COMPONENT_DIRS $ENV{IDF_PATH}/examples/common_components/protocol_examples_common)
#    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DFOUND_PROTOCOL_EXAMPLES_DIR")
#else()
#    message("NOT FOUND: PROTOCOL_EXAMPLES_DIR=${PROTOCOL_EXAMPLES_DIR}")
#endif()

# Not only is a project-level "set(COMPONENTS" not needed here, this will cause
# an unintuitive error about  Unknown CMake command "esptool_py_flash_project_args".
include($ENV{IDF_PATH}/tools/cmake/project.cmake)

project(wolfssl_benchmark)
