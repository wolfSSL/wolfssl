EXTRA_DIST = certs/*.pem certs/*.der certs/*.txt certs/*.raw \
    lib/dummy *.sln *.vcproj cyassl-iphone.xcodeproj/project.pbxproj \
    doc/*.txt swig/README swig/*.i swig/cyassl_adds.c swig/*.sh swig/runme.* \
    swig/python_cyassl.vcproj swig/rsasign.py

ACLOCAL_AMFLAGS = -I m4

include src/include.am
include ctaocrypt/test/include.am
include ctaocrypt/benchmark/include.am
include examples/client/include.am
include examples/server/include.am
include examples/echoclient/include.am
include examples/echoserver/include.am
include testsuite/include.am
include sslSniffer/sslSnifferTest/include.am

# !!!! first line of rule has to start with a hard (real) tab, not spaces
basic:
	cd src; $(MAKE); cd ../testsuite; $(MAKE); cd ../

# !!!! first line of rule has to start with a hard (real) tab, not spaces
egs:
	$(MAKE) examples/client/client; \
	$(MAKE) examples/echoclient/echoclient;\
	$(MAKE) examples/server/server; \
	$(MAKE) examples/echoserver/echoserver;

openssl-links:
	cd lib; ln -s ../src/.libs/libcyassl.a libcrypto.a; \
    ln -s ../src/.libs/libcyassl.a libssl.a; \
    ln -s ../src/.libs/libcyassl.a libcyassl.a; cd ../

#  !!! test -e with a .name like .libs then a * like *dylib fails so just
#      look for the .dylib on OS X, and .so otherwise but copy all parts
install:
	$(mkinstalldirs) $(DESTDIR)$(includedir)/openssl $(DESTDIR)$(libdir); \
    cp -fpR include/openssl/* $(DESTDIR)$(includedir)/openssl; \
    cp -fpR ctaocrypt/include/*.h $(DESTDIR)$(includedir); \
    rm $(DESTDIR)$(includedir)/asn.h; \
    rm $(DESTDIR)$(includedir)/coding.h; \
    rm $(DESTDIR)$(includedir)/error.h; \
    rm $(DESTDIR)$(includedir)/misc.h; \
    cp -fpR src/libcyassl.la $(DESTDIR)$(libdir); \
    if test -e src/.libs/libcyassl.a; then \
    cp -fp src/.libs/libcyassl.a $(DESTDIR)$(libdir); fi; \
    if test -e src/.libs/libcyassl.so; then \
    cp -fpR src/.libs/libcyassl.so* $(DESTDIR)$(libdir); fi; \
    if test -e src/.libs/libcyassl.dylib; then \
    cp -fpR src/.libs/libcyassl.*dylib $(DESTDIR)$(libdir); fi;
