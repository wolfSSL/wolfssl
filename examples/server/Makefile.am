INCLUDES = -I../../include -I../../include/openssl
bin_PROGRAMS    = server
server_SOURCES  = server.c
server_LDFLAGS      = -L../../src
server_LDADD        = ../../src/libcyassl.la
server_DEPENDENCIES = ../../src/libcyassl.la
EXTRA_DIST = server.sln *.vcproj
