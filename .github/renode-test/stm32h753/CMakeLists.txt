cmake_minimum_required(VERSION 3.18)
project(wolfcrypt_stm32h753 LANGUAGES C ASM)

set(WOLFSSL_ROOT "/opt/wolfssl" CACHE PATH "wolfSSL source")

set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
enable_language(ASM)

# Include paths for CMSIS device headers and STM32 HAL
# Order matters: CMSIS must come before HAL
include_directories(BEFORE
    ${CMAKE_SOURCE_DIR}
    /opt/CMSIS_5/CMSIS/Core/Include  # Core CMSIS (core_cm7.h, etc.) - must be first
    /opt/cmsis-device-h7/Include     # Device-specific CMSIS (stm32h7xx.h)
    /opt/STM32CubeH7/Drivers/STM32H7xx_HAL_Driver/Inc/Legacy
    /opt/STM32CubeH7/Drivers/STM32H7xx_HAL_Driver/Inc
)

# STM32 HAL source files (minimal set for CRYP and HASH)
# Note: These files are cloned in the Dockerfile before CMake runs
set(HAL_SRC_DIR /opt/STM32CubeH7/Drivers/STM32H7xx_HAL_Driver/Src)

# Check if HAL directory exists, then add source files
if(EXISTS ${HAL_SRC_DIR})
    set(HAL_SOURCES
        ${HAL_SRC_DIR}/stm32h7xx_hal.c
        ${HAL_SRC_DIR}/stm32h7xx_hal_rcc.c
        ${HAL_SRC_DIR}/stm32h7xx_hal_rcc_ex.c
        ${HAL_SRC_DIR}/stm32h7xx_hal_cortex.c
        ${HAL_SRC_DIR}/stm32h7xx_hal_dma.c
        ${HAL_SRC_DIR}/stm32h7xx_hal_dma_ex.c
        ${HAL_SRC_DIR}/stm32h7xx_hal_rng.c
        # CRYP HAL files enabled for AES_GCM only
        ${HAL_SRC_DIR}/stm32h7xx_hal_cryp.c
        ${HAL_SRC_DIR}/stm32h7xx_hal_cryp_ex.c
        # HASH HAL files disabled - Renode doesn't implement HASH peripheral
        # ${HAL_SRC_DIR}/stm32h7xx_hal_hash.c
        # ${HAL_SRC_DIR}/stm32h7xx_hal_hash_ex.c
    )
else()
    message(WARNING "HAL source directory not found: ${HAL_SRC_DIR}")
    set(HAL_SOURCES "")
endif()

# wolfSSL build options
set(WOLFSSL_USER_SETTINGS ON CACHE BOOL "Use user_settings.h")
set(WOLFSSL_CRYPT_TESTS OFF CACHE BOOL "")
set(WOLFSSL_EXAMPLES OFF CACHE BOOL "")
set(BUILD_SHARED_LIBS OFF CACHE BOOL "")

add_subdirectory(${WOLFSSL_ROOT} ${CMAKE_BINARY_DIR}/wolfssl-build EXCLUDE_FROM_ALL)
target_include_directories(wolfssl PRIVATE
    /opt/CMSIS_5/CMSIS/Core/Include  # Core CMSIS first
    /opt/cmsis-device-h7/Include     # Device CMSIS
    /opt/STM32CubeH7/Drivers/STM32H7xx_HAL_Driver/Inc/Legacy
    /opt/STM32CubeH7/Drivers/STM32H7xx_HAL_Driver/Inc
    ${CMAKE_SOURCE_DIR}  # For stm32h7xx_hal_conf.h
)
# Suppress the GENSEED_FORTEST warning (expected for emulation/test builds)
target_compile_options(wolfssl PRIVATE -Wno-cpp)

# wolfSSL STM32 port source file (needed for HASH and CRYPTO hardware acceleration)
set(WOLFSSL_STM32_PORT_SRC ${WOLFSSL_ROOT}/wolfcrypt/src/port/st/stm32.c)

add_executable(wolfcrypt_test.elf
    startup_stm32h753.c
    main.c
    ${WOLFSSL_ROOT}/wolfcrypt/test/test.c
    ${HAL_SOURCES}
    ${WOLFSSL_STM32_PORT_SRC}
)

target_include_directories(wolfcrypt_test.elf PRIVATE
    ${CMAKE_SOURCE_DIR}
    ${WOLFSSL_ROOT}
    /opt/STM32CubeH7/Drivers/STM32H7xx_HAL_Driver/Inc
    /opt/STM32CubeH7/Drivers/STM32H7xx_HAL_Driver/Inc/Legacy
)

target_compile_definitions(wolfcrypt_test.elf PRIVATE
    WOLFSSL_USER_SETTINGS
    STM32H753xx
    USE_HAL_DRIVER
    USE_HAL_CONF  # Enable HAL configuration
    # NO_AES_CBC is defined in user_settings.h, no need to define it here
)

# HAL source files need the same compile options and must include stdint.h
# Disable all warnings for HAL files (third-party code we don't control)
set_source_files_properties(${HAL_SOURCES} PROPERTIES
    COMPILE_FLAGS "-mcpu=cortex-m7 -mthumb -mfpu=fpv5-d16 -mfloat-abi=hard -ffunction-sections -fdata-sections -Os -include stdint.h -w"
)

target_compile_options(wolfcrypt_test.elf PRIVATE
    -mcpu=cortex-m7 -mthumb -mfpu=fpv5-d16 -mfloat-abi=hard
    -ffunction-sections -fdata-sections -Os
)

target_link_options(wolfcrypt_test.elf PRIVATE
    -T${CMAKE_SOURCE_DIR}/stm32h753.ld
    -Wl,--gc-sections
    -nostartfiles
    -specs=nano.specs
    -specs=nosys.specs
)

target_link_libraries(wolfcrypt_test.elf PRIVATE wolfssl m c gcc nosys)

