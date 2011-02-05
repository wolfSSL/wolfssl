INCLUDES = -I../include -I../ctaocrypt/include -I../include/openssl
bin_PROGRAMS    = testsuite
testsuite_SOURCES = testsuite.c ../ctaocrypt/test/test.c \
    ../examples/client/client.c ../examples/server/server.c \
    ../examples/echoclient/echoclient.c ../examples/echoserver/echoserver.c
AM_CFLAGS  = -DNO_MAIN_DRIVER
testsuite_LDFLAGS      = -L../src
testsuite_LDADD        = ../src/libcyassl.la
testsuite_DEPENDENCIES = ../src/libcyassl.la 
EXTRA_DIST = input quit testsuite.sln *.vcproj
