### wolfSSL with Arduino

##### reformat-wolfssl.sh
This is a shell script that will re-organize the wolfSSL library to be 
compatible with Arduino projects. The Arduino IDE requires a library's source
files to be in the library's root directory with a header file in the name of 
the library. This script moves all src/ files to the root wolfssl directory and 
creates a stub header file called wolfssl.h.

To configure wolfSSL with Arduino, enter the following from within the 
wolfssl/IDE/ARDUINO directory:

    sh reformat-wolfssl.sh
