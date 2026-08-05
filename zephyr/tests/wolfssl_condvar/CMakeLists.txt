cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wolfssl_condvar)

target_sources(app PRIVATE src/main.c)
add_definitions(-DWOLFSSL_USER_SETTINGS)
