# CMakeList.txt
#
# Copyright (C) 2006-2020 wolfSSL Inc.
#
# This file is part of wolfSSL. (formerly known as CyaSSL)
#
# Usage:
# $ mkdir build
# $ cd build
# $ cmake ..
# $ cmake --build .

# To build library only and not build examples and test apps use:
# $ cmake .. -DBUILD_TESTS=NO

# To build with debugging use:
# $ cmake .. -DCMAKE_BUILD_TYPE=Debug


cmake_minimum_required (VERSION 2.6)

####################################################
# Project
####################################################
project(wolfssl)
find_package (Threads)

####################################################
# Compiler
####################################################
# Let CMake choose default compiler

# Silence ranlib warning "has no symbols"
SET(CMAKE_C_ARCHIVE_CREATE   "<CMAKE_AR> Scr <TARGET> <LINK_FLAGS> <OBJECTS>")
SET(CMAKE_CXX_ARCHIVE_CREATE "<CMAKE_AR> Scr <TARGET> <LINK_FLAGS> <OBJECTS>")
SET(CMAKE_C_ARCHIVE_FINISH   "<CMAKE_RANLIB> -no_warning_for_no_symbols -c <TARGET>")
SET(CMAKE_CXX_ARCHIVE_FINISH "<CMAKE_RANLIB> -no_warning_for_no_symbols -c <TARGET>")

####################################################
# Cross Compile Example
####################################################

#set(CMAKE_SYSTEM_NAME Linux)
#set(CMAKE_SYSTEM_PROCESSOR arm)
#set(CMAKE_C_COMPILER "/opt/arm-linux-musleabihf-cross/bin/arm-linux-musleabihf-gcc")
#set(CMAKE_CXX_COMPILER "/opt/arm-linux-musleabihf-cross/bin/arm-linux-musleabihf-g++")
#set(CMAKE_SYSROOT "/opt/arm-linux-musleabihf-cross/arm-linux-musleabihf/")
# Example for setting CFLAGS
#set(CMAKE_C_FLAGS "-std=gnu89 ${CMAKE_C_FLAGS}")
# Example for map file and custom linker script
#set(CMAKE_EXE_LINKER_FLAGS " -Xlinker -Map=output.map -T\"${CMAKE_CURRENT_SOURCE_DIR}/linker.ld\"")

####################################################
# Build Options
####################################################
SET(BUILD_TESTS YES CACHE BOOL "Build test applications")

if(EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/wolfssl/options.h")
    # Copy generated ./options.h
    configure_file(${CMAKE_CURRENT_SOURCE_DIR}/wolfssl/options.h 
                   ${CMAKE_CURRENT_BINARY_DIR}/user_settings.h)
else()
   # Use template
   configure_file(${CMAKE_CURRENT_SOURCE_DIR}/wolfssl/options.h.in 
                  ${CMAKE_CURRENT_BINARY_DIR}/user_settings.h)
endif()

add_definitions(-DWOLFSSL_USER_SETTINGS)
add_definitions(-DWOLFSSL_IGNORE_FILE_WARN)
if(CMAKE_HAVE_PTHREAD_H)
  add_definitions(-DHAVE_PTHREAD)
endif()

####################################################
# Source Files
####################################################
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/.)
include_directories(${CMAKE_CURRENT_BINARY_DIR}/.)

file(GLOB LIB_SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/src/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/wolfcrypt/src/*.c)

file(GLOB TEST_SOURCE_FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/tests/*.c
    ${CMAKE_CURRENT_SOURCE_DIR}/examples/server/server.c
    ${CMAKE_CURRENT_SOURCE_DIR}/examples/client/client.c)

####################################################
# Output Files
####################################################

# Build wolfssl library
add_library(wolfssl ${LIB_SOURCE_FILES})

if(WIN32)
    # For Windows link ws2_32
    target_link_libraries(wolfssl PUBLIC $<$<PLATFORM_ID:Windows>:ws2_32>)
else()
    # DH requires math (m) library
    target_link_libraries(wolfssl PUBLIC m)
endif()

# Optionally build example and test applications
if(BUILD_TESTS)
    # Build wolfCrypt test
    add_executable(wolfcrypttest
        ${CMAKE_CURRENT_SOURCE_DIR}/wolfcrypt/test/test.c)
    target_link_libraries(wolfcrypttest wolfssl)

    # Build wolfCrypt benchmark
    add_executable(wolfcryptbench
        ${CMAKE_CURRENT_SOURCE_DIR}/wolfcrypt/benchmark/benchmark.c)
    target_link_libraries(wolfcryptbench wolfssl)

    # Build wolfSSL Client example
    add_executable(client
        ${CMAKE_CURRENT_SOURCE_DIR}/examples/client/client.c)
    target_link_libraries(client wolfssl)

    # Build wolfSSL Server example
    add_executable(server
        ${CMAKE_CURRENT_SOURCE_DIR}/examples/server/server.c)
    target_link_libraries(server wolfssl)

    # Build Echo Client Example
    add_executable(echoclient
        ${CMAKE_CURRENT_SOURCE_DIR}/examples/echoclient/echoclient.c)
    target_link_libraries(echoclient wolfssl)

    # Build Echo Server Example
    add_executable(echoserver
        ${CMAKE_CURRENT_SOURCE_DIR}/examples/echoserver/echoserver.c)
    target_link_libraries(echoserver wolfssl)

    # Build TLS benchmark example
    add_executable(tls_bench
        ${CMAKE_CURRENT_SOURCE_DIR}/examples/benchmark/tls_bench.c)
    target_link_libraries(tls_bench wolfssl)
    target_link_libraries(tls_bench Threads::Threads)

    # Build Unit Tests
    add_executable(unit_test
        ${TEST_SOURCE_FILES})
    set_target_properties( unit_test PROPERTIES COMPILE_FLAGS "-DNO_MAIN_DRIVER" )
    target_link_libraries(unit_test wolfssl)
    target_link_libraries(unit_test Threads::Threads)
endif()

# TODO: Add install() for library, headers and test applications
