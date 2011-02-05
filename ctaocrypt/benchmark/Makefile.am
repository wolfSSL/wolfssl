INCLUDES = -I../include
bin_PROGRAMS = benchmark
benchmark_SOURCES = benchmark.c
benchmark_LDFLAGS      = -L../src
benchmark_LDADD        = ../../src/libcyassl.la
benchmark_DEPENDENCIES = ../../src/libcyassl.la
EXTRA_DIST =  *.der benchmark.sln benchmark.vcproj
