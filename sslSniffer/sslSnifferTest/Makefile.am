INCLUDES = -I../../include
bin_PROGRAMS    = snifftest
snifftest_SOURCES  = snifftest.c
snifftest_LDFLAGS  = -L../../src

if BUILD_SNIFFER
snifftest_LDADD        = ../../src/libcyassl.la -lpcap
snifftest_DEPENDENCIES = ../../src/libcyassl.la
endif

EXTRA_DIST = sslSniffTest.vcproj
