SUBDIRS = src ctaocrypt examples testsuite sslSniffer
EXTRA_DIST = certs/*.pem certs/*.der certs/*.txt certs/*.raw \
    lib/dummy *.sln *.vcproj cyassl-iphone.xcodeproj/project.pbxproj \
    doc/*.pdf swig/README swig/*.i swig/cyassl_adds.c swig/*.sh swig/runme.* \
    swig/python_cyassl.vcproj swig/rsasign.py

ACLOCAL_AMFLAGS = -I m4

# !!!! first line of rule has to start with a hard (real) tab, not spaces
basic:
	cd src; $(MAKE); cd ../testsuite; $(MAKE); cd ../

openssl-links:
	cd lib; ln -s ../src/.libs/libcyassl.a libcrypto.a; \
    ln -s ../src/.libs/libcyassl.a libssl.a; \
    ln -s ../src/.libs/libcyassl.a libcyassl.a; cd ../

#  !!! test -e with a .name like .libs then a * like *dylib fails so just
#      look for the .dylib on OS X, and .so otherwise but copy all parts
install:
	$(mkinstalldirs) $(DESTDIR)$(includedir) $(DESTDIR)$(libdir); \
    cp -fpR include/* $(DESTDIR)$(includedir); \
    cp -fpR ctaocrypt/include/* $(DESTDIR)$(includedir); \
    cp -fpR src/libcyassl.la $(DESTDIR)$(libdir); \
    if test -e src/.libs/libcyassl.a; then \
    cp -fp src/.libs/libcyassl.a $(DESTDIR)$(libdir); fi; \
    if test -e src/.libs/libcyassl.so; then \
    cp -fpR src/.libs/libcyassl.so* $(DESTDIR)$(libdir); fi; \
    if test -e src/.libs/libcyassl.dylib; then \
    cp -fpR src/.libs/libcyassl.*dylib $(DESTDIR)$(libdir); fi;
