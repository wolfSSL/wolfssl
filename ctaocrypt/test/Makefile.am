INCLUDES = -I../include -I../../include -I../../include/openssl
bin_PROGRAMS = test
test_SOURCES = test.c
test_LDFLAGS = -L../src
test_LDADD        = ../../src/libcyassl.la
test_DEPENDENCIES = ../../src/libcyassl.la
EXTRA_DIST =  test.sln test.vcproj
