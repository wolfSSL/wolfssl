# tropic01 callbacks



## How to build:

1. Build libtropic project with all dependencies for the targeted platfrom (for example, Raspberry Pi 3/4/5). Preferably all static targets must be built with -fPIC option
2. Goto wolfssl main folder 
3. ./autogen.sh
4. ./configure --with-tropic01=/home/pi/git/libtropic --enable-cryptocb --enable-static --disable-crypttests --disable-examples --disable-shared
Note. Please replace '/home/pi/git/libtropic' with an absolute path to your libtropic folder if necessary 
5. make
6. the built library should be in ./wolfssl/src/.libs/libwolfssl.a

## How to use:



 
 
