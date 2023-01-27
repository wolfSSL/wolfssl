
#
# wolfssl client test
#
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_USER_SETTINGS")

set(COMPONENT_SRCS "client-tls.c" "wifi_connect.c")
set(COMPONENT_ADD_INCLUDEDIRS "." "./include")

if( EXISTS "${CMAKE_HOME_DIRECTORY}/components/wolfssl/" AND EXISTS "$ENV{IDF_PATH}/components/wolfssl/" )
    #
    # wolfSSL found in both ESP-IDF and local project - needs to be resolved by user
    #
    message(STATUS "")
    message(STATUS "WARNING: Found components/wolfssl in both local project and IDF_PATH")
    message(STATUS "")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_MULTI_INSTALL_WARNING")
endif()

register_component()

set (git_cmd "git")
set (git_rev_parse "rev-parse")
set (git_short "--short")
set (git_HEAD "HEAD")
set (git_show "show")
set (git_no_patch "--no-patch")
set (git_no_notes "--no-notes")
set (git_pretty "--pretty=\'\%cd\'" )

if(NOT CMAKE_BUILD_EARLY_EXPANSION)
    # LIBWOLFSSL_VERSION_GIT_HASH
    execute_process(COMMAND ${git_cmd} ${git_rev_parse} ${git_HEAD} OUTPUT_VARIABLE LIBWOLFSSL_VERSION_GIT_HASH_VAR RESULT_VARIABLE WOLFSSL_GIT_PEEK_RESULT ERROR_QUIET )
    string(REPLACE "\n" ""  LIBWOLFSSL_VERSION_GIT_HASH  ${LIBWOLFSSL_VERSION_GIT_HASH_VAR})
    string(COMPARE EQUAL "${WOLFSSL_GIT_PEEK_RESULT}" "0" WOLFSSL_FOUND_GIT_VALUE)
    if(${WOLFSSL_FOUND_GIT_VALUE})
        message(STATUS "Found LIBWOLFSSL_VERSION_GIT_HASH=${LIBWOLFSSL_VERSION_GIT_HASH}")
        #idf_build_set_property(COMPILE_DEFINITIONS "LIBWOLFSSL_VERSION_GIT_HASH=\"${LIBWOLFSSL_VERSION_GIT_HASH_VAR1}\"" APPEND)
        #idf_build_set_property(COMPILE_DEFINITIONS "LIBWOLFSSL_VERSION_GIT_HASH=\"${LIBWOLFSSL_VERSION_GIT_HASH_VAR}\"" APPEND)
        add_definitions(-DLIBWOLFSSL_VERSION_GIT_HASH=\"${LIBWOLFSSL_VERSION_GIT_HASH}\")
    endif()

    # LIBWOLFSSL_VERSION_GIT_SHORT_HASH
    execute_process(COMMAND ${git_cmd} ${git_rev_parse} ${git_short} ${git_HEAD} OUTPUT_VARIABLE LIBWOLFSSL_VERSION_GIT_SHORT_HASH_VAR RESULT_VARIABLE WOLFSSL_GIT_PEEK_RESULT ERROR_QUIET )
    string(REPLACE "\n" ""  LIBWOLFSSL_VERSION_GIT_SHORT_HASH  ${LIBWOLFSSL_VERSION_GIT_SHORT_HASH_VAR})
    string(COMPARE EQUAL "${WOLFSSL_GIT_PEEK_RESULT}" "0" WOLFSSL_FOUND_GIT_VALUE)
    if(${WOLFSSL_FOUND_GIT_VALUE})
        message(STATUS "Found LIBWOLFSSL_VERSION_GIT_SHORT_HASH=${LIBWOLFSSL_VERSION_GIT_SHORT_HASH}")
        add_definitions(-DLIBWOLFSSL_VERSION_GIT_SHORT_HASH=\"${LIBWOLFSSL_VERSION_GIT_SHORT_HASH}\")
    endif()

    # LIBWOLFSSL_VERSION_GIT_SHORT_HASH
    execute_process(COMMAND ${git_cmd} ${git_show} ${git_no_patch} ${git_no_notes} ${git_pretty} OUTPUT_VARIABLE LIBWOLFSSL_VERSION_GIT_HASH_DATE_VAR RESULT_VARIABLE WOLFSSL_GIT_PEEK_RESULT  )
    string(REPLACE "\n" ""  LIBWOLFSSL_VERSION_GIT_HASH_DATE  ${LIBWOLFSSL_VERSION_GIT_HASH_DATE_VAR})
    string(COMPARE EQUAL "${WOLFSSL_GIT_PEEK_RESULT}" "0" WOLFSSL_FOUND_GIT_VALUE)
    if(${WOLFSSL_FOUND_GIT_VALUE})
        message(STATUS "Found LIBWOLFSSL_VERSION_GIT_HASH_DATE=${LIBWOLFSSL_VERSION_GIT_HASH_DATE}")
        add_definitions(-DLIBWOLFSSL_VERSION_GIT_HASH_DATE=\"${LIBWOLFSSL_VERSION_GIT_HASH_DATE}\")
    endif()
endif()

message(STATUS "")

