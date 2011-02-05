INCLUDES = -I../../include -I../../include/openssl
bin_PROGRAMS    = echoclient
echoclient_SOURCES  = echoclient.c
echoclient_LDFLAGS     = -L../../src 
echoclient_LDADD       = ../../src/libcyassl.la
echoclient_DEPENDENCIES= ../../src/libcyassl.la
EXTRA_DIST = input quit echoclient.sln *.vcproj
