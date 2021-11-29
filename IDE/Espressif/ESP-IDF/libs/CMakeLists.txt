#
# cmake for wolfssl
# 
cmake_minimum_required(VERSION 3.5)
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_USER_SETTINGS")

set(CMAKE_CURRENT_SOURCE_DIR ".")
set(WOLFSSL_ROOT ${CMAKE_CURRENT_SOURCE_DIR})
set(INCLUDE_PATH ${WOLFSSL_ROOT})

set(COMPONENT_SRCDIRS "./src/"
                      "./wolfcrypt/src/"
                      "./wolfcrypt/src/port/Espressif/"
                      "./wolfcrypt/src/port/atmel/"
                      )

set(COMPONENT_REQUIRES lwip)

if(IS_DIRECTORY ${IDF_PATH}/components/freertos/FreeRTOS-Kernel/)
    set(COMPONENT_ADD_INCLUDEDIRS
        "."
        "./include"
        "../freertos/FreeRTOS-Kernel/include/freertos"
       "${WOLFSSL_ROOT}"
       )
else()

   set(COMPONENT_ADD_INCLUDEDIRS
       "."
       "./include"
       "../freertos/include/freertos"
       "${WOLFSSL_ROOT}"
      )
endif()

if(IS_DIRECTORY ${IDF_PATH}/components/cryptoauthlib)
    list(APPEND COMPONENT_ADD_INCLUDEDIRS "../cryptoauthlib/lib")
endif()

set(COMPONENT_SRCEXCLUDE
    "wolfcrypt/src/aes_asm.S"
    "wolfcrypt/src/evp.c"
    "wolfcrypt/src/misc.c"
    "src/bio.c"
    )

register_component()
