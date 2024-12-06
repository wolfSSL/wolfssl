# wolfSSL Espressif Example Project/main CMakeLists.txt
#   v1.1
#
# wolfssl crypt test
#
message(STATUS "Begin wolfSSL main CMakeLists.txt")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_USER_SETTINGS")

if(WIN32)
    # Windows-specific configuration here
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_CMAKE_SYSTEM_NAME_WINDOWS")
    message(STATUS "Detected Windows")
endif()
if(CMAKE_HOST_UNIX)
    message(STATUS "Detected UNIX")
endif()
if(APPLE)
    message(STATUS "Detected APPLE")
endif()
if(CMAKE_HOST_UNIX AND (NOT APPLE) AND EXISTS "/proc/sys/fs/binfmt_misc/WSLInterop")
    # Windows-specific configuration here
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_CMAKE_SYSTEM_NAME_WSL")
    message(STATUS "Detected WSL")
endif()
if(CMAKE_HOST_UNIX AND (NOT APPLE) AND (NOT WIN32))
    # Windows-specific configuration here
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_CMAKE_SYSTEM_NAME_LINUX")
    message(STATUS "Detected Linux")
endif()
if(APPLE)
    # Windows-specific configuration here
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_CMAKE_SYSTEM_NAME_APPLE")
    message(STATUS "Detected Apple")
endif()
set (git_cmd "git")

if( EXISTS "${CMAKE_HOME_DIRECTORY}/components/wolfssl/" AND EXISTS "$ENV{IDF_PATH}/components/wolfssl/" )
    #
    # wolfSSL found in both ESP-IDF and local project - needs to be resolved by user
    #
    message(STATUS "")
    message(STATUS "WARNING: Found components/wolfssl in both local project and IDF_PATH")
    message(STATUS "")
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_MULTI_INSTALL_WARNING")
endif()

# The wolfSL component name is named "mywolfssl" on the staging site for Managed Components.
if( NOT EXISTS "../components/wolfssl" AND ("$ENV{IDF_COMPONENT_REGISTRY_URL}" STREQUAL "https://components-staging.espressif.com") )
    message(STATUS "WARNING: Using a staging instance of wolfssl.")
    set(MAIN_WOLFSSL_COMPONENT_NAME "mywolfssl")
else()
    message(STATUS "Using release wolfssl component.")
    set(MAIN_WOLFSSL_COMPONENT_NAME "wolfssl")
endif()

## register_component()
idf_component_register(SRCS main.c
                       INCLUDE_DIRS "."
                            "./include"
                       PRIV_REQUIRES driver "${MAIN_WOLFSSL_COMPONENT_NAME}")

#
# LIBWOLFSSL_SAVE_INFO(VAR_OUPUT THIS_VAR VAR_RESULT)
#
# Save the THIS_VAR as a string in a macro called VAR_OUPUT
#
# VAR_OUPUT:  the name of the macro to define
# THIS_VAR:   the OUTPUT_VARIABLE result from a execute_process()
# VAR_RESULT: the RESULT_VARIABLE from a execute_process(); "0" if successful.
#
function ( LIBWOLFSSL_SAVE_INFO VAR_OUPUT THIS_VAR VAR_RESULT )
    # is the RESULT_VARIABLE output value 0? If so, IS_VALID_VALUE is true.
    string(COMPARE EQUAL "${VAR_RESULT}" "0" IS_VALID_VALUE)

    # if we had a successful operation, save the THIS_VAR in VAR_OUPUT
    if(${IS_VALID_VALUE})
        # strip newline chars in THIS_VAR parameter and save in VAR_VALUE
        string(REPLACE "\n" ""  VAR_VALUE  ${THIS_VAR})

        # we'll could percolate the value to the parent for possible later use
        # set(${VAR_OUPUT} ${VAR_VALUE} PARENT_SCOPE)

        # but we're only using it here in this function
        set(${VAR_OUPUT} ${VAR_VALUE})

        # we'll print what we found to the console
        message(STATUS "Found ${VAR_OUPUT}=${VAR_VALUE}")

        # the interesting part is defining the VAR_OUPUT name a value to use in the app
        add_compile_definitions(${VAR_OUPUT}=\"${VAR_VALUE}\")
    else()
        # if we get here, check the execute_process command and parameters.
        message(STATUS "LIBWOLFSSL_SAVE_INFO encountered a non-zero VAR_RESULT.")
        message(STATUS "Setting ${VAR_OUPUT} to \"Unknown\"")
        set(${VAR_OUPUT} "Unknown")
    endif()
endfunction() # LIBWOLFSSL_SAVE_INFO

execute_process(
    COMMAND ${git_cmd} "rev-parse" "--is-inside-work-tree"
    OUTPUT_VARIABLE IS_GIT_REPO
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)

# Save some project-specific details. Repo may be different than component, or may not even be a repo at all:
if(NOT CMAKE_BUILD_EARLY_EXPANSION AND (IS_GIT_REPO STREQUAL "true"))
    # LIBWOLFSSL_VERSION_GIT_HASH
    execute_process(COMMAND ${git_cmd} "rev-parse" "HEAD" OUTPUT_VARIABLE TMP_OUT RESULT_VARIABLE TMP_RES ERROR_QUIET )
    LIBWOLFSSL_SAVE_INFO(LIBWOLFSSL_VERSION_GIT_HASH "${TMP_OUT}" "${TMP_RES}")

    # LIBWOLFSSL_VERSION_GIT_SHORT_HASH
    execute_process(COMMAND ${git_cmd} "rev-parse" "--short" "HEAD" OUTPUT_VARIABLE TMP_OUT RESULT_VARIABLE TMP_RES ERROR_QUIET )
    LIBWOLFSSL_SAVE_INFO(LIBWOLFSSL_VERSION_GIT_SHORT_HASH "${TMP_OUT}" "${TMP_RES}")

    # LIBWOLFSSL_VERSION_GIT_HASH_DATE
    execute_process(COMMAND ${git_cmd} "show" "--no-patch" "--no-notes" "--pretty=\'\%cd\'" OUTPUT_VARIABLE TMP_OUT RESULT_VARIABLE TMP_RES  )
    LIBWOLFSSL_SAVE_INFO(LIBWOLFSSL_VERSION_GIT_HASH_DATE "${TMP_OUT}" "${TMP_RES}")
endif()

message(STATUS "")

message(STATUS "End wolfSSL main CMakeLists.txt")
