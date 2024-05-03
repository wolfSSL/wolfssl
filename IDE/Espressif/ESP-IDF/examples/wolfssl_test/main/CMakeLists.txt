#
# wolfssl crypt test
#
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DWOLFSSL_USER_SETTINGS")

idf_component_register(SRCS
                         "main.c"
                       INCLUDE_DIRS
                         ".")
