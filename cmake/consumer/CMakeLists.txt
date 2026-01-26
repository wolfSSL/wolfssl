cmake_minimum_required(VERSION 3.10)

project(wolfssl_consumer C)

find_package(wolfssl CONFIG REQUIRED)

add_executable(wolfssl_consumer main.c)
target_link_libraries(wolfssl_consumer PRIVATE wolfssl::wolfssl)
