INCLUDES = -I../../include -I../../include/openssl
bin_PROGRAMS    = client
client_SOURCES  = client.c
client_LDFLAGS      = -L../../src
client_LDADD        = ../../src/libcyassl.la
client_DEPENDENCIES = ../../src/libcyassl.la
EXTRA_DIST = client.sln *.vcproj
