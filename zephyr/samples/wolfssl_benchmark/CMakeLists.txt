cmake_minimum_required(VERSION 3.13.1)

# Select version-specific Kconfig fragment before loading Zephyr
if(EXISTS $ENV{ZEPHYR_BASE}/VERSION)
    file(READ $ENV{ZEPHYR_BASE}/VERSION zephyr_version_file)
    string(REGEX MATCH "VERSION_MAJOR = ([0-9]+)" _ ${zephyr_version_file})
    set(ZEPHYR_VER_MAJOR ${CMAKE_MATCH_1})
    string(REGEX MATCH "VERSION_MINOR = ([0-9]+)" _ ${zephyr_version_file})
    set(ZEPHYR_VER_MINOR ${CMAKE_MATCH_1})
endif()

if(ZEPHYR_VER_MAJOR GREATER_EQUAL 4 OR
   (ZEPHYR_VER_MAJOR EQUAL 3 AND
    ZEPHYR_VER_MINOR GREATER 5))
    set(OVERLAY_CONFIG
        ${CMAKE_CURRENT_SOURCE_DIR}/zephyr_v4.1.conf)
else()
    set(OVERLAY_CONFIG
        ${CMAKE_CURRENT_SOURCE_DIR}/zephyr_legacy.conf)
endif()

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(wolfssl_benchmark)

target_sources(app PRIVATE ${ZEPHYR_WOLFSSL_MODULE_DIR}/wolfcrypt/benchmark/benchmark.c)
target_include_directories(app PRIVATE ${ZEPHYR_WOLFSSL_MODULE_DIR}/wolfcrypt/benchmark)
target_sources(app PRIVATE ${app_sources})
add_definitions(-DWOLFSSL_USER_SETTINGS)
