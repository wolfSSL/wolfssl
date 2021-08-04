cmake_minimum_required(VERSION 3.13.1)
include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)
project(wolfssl_test)

target_sources(app PRIVATE ${ZEPHYR_WOLFSSL_MODULE_DIR}/wolfcrypt/test/test.c)
target_include_directories(app PRIVATE ${ZEPHYR_WOLFSSL_MODULE_DIR}/wolfcrypt/test)
target_sources(app PRIVATE ${app_sources})
add_definitions(-DWOLFSSL_USER_SETTINGS)

