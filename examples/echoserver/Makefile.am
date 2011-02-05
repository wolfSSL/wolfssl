INCLUDES = -I../../include -I../../include/openssl
bin_PROGRAMS    = echoserver
echoserver_SOURCES  = echoserver.c
echoserver_LDFLAGS  = -L../../src
echoserver_LDADD       = ../../src/libcyassl.la
echoserver_DEPENDENCIES= ../../src/libcyassl.la
EXTRA_DIST = echoserver.sln *.vcproj
