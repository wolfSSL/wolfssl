cmake_minimum_required(VERSION 3.10)

project(wolfssl_consumer C)

find_package(wolfssl CONFIG REQUIRED)
if(NOT wolfssl_VERSION MATCHES "^[0-9]+\\.[0-9]+\\.[0-9]+$")
    message(FATAL_ERROR "wolfssl package version '${wolfssl_VERSION}' lacks the patch level")
endif()

add_executable(wolfssl_consumer main.c)
target_link_libraries(wolfssl_consumer PRIVATE wolfssl::wolfssl)
